// Package cli is a command tree an application embeds in its own command line under its own name
// and branding. It manages a team's keys, members and instances through the Account
// API, and signs the command line in to one instance, which issues the application's own token.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/sdk"
	"github.com/clorhq/apps/sdk/account"
	"github.com/jacob2161/atomicfile"
)

// Output formats for --stdout-format.
const (
	formatText  = "text"
	formatJSON  = "json"
	formatJSONL = "jsonl"
)

// Flag names shared by several commands.
const (
	flagStdoutFormat = "stdout-format"
	flagKey          = "key"
	flagNoBrowser    = "no-browser"
	flagWait         = "wait"
	flagTimeout      = "timeout"
	flagTeamName     = "name"
)

// Defaults for paths, files and waiting.
const (
	sessionFilename       = "session.json"
	sessionFileMode       = 0o600
	sessionDirectoryMode  = 0o700
	defaultWaitTimeout    = 5 * time.Minute
	readinessPollInterval = 3 * time.Second
	requestTimeout        = 30 * time.Second
)

// Args brands and locates the command tree for one app.
type Args struct {
	// Presentation optionally delegates output and option validation to the embedding app.
	Presentation *Presentation
	// Name is the executable name, such as backupd. It also names the configuration directory and
	// the NAME_ACCOUNT_KEY environment variable.
	Name string
	// DisplayName is the product name shown in messages.
	DisplayName string
	// APIOrigin is the app's API domain, such as https://api.example.com.
	APIOrigin string
	// WebsiteOrigin is the app's website, such as https://example.com.
	WebsiteOrigin string
	// TerminalAuthPath overrides sdk.DefaultTerminalAuthPath when the instance uses a custom mount point.
	TerminalAuthPath string
	// ConfigurationDirectory defaults to the user configuration directory joined with Name.
	ConfigurationDirectory string
	// HTTPClient is optional.
	HTTPClient *http.Client
	// OpenBrowser is optional and defaults to the platform's URL opener.
	OpenBrowser func(ctx context.Context, address string) error
}

// AddCommands adds the account, team, instance and login commands to an application's root command.
func AddCommands(root *cobra.Command, args *Args) {
	root.AddCommand(NewAccountCommand(args), NewTeamCommand(args), NewInstanceCommand(args), NewLoginCommand(args))
}

// InstanceSession is a stored terminal session for one instance.
type InstanceSession struct {
	InstanceID string    `json:"instance_id"`
	Hostname   string    `json:"hostname"`
	Token      string    `json:"token"`
	User       sdk.User  `json:"user"`
	SignedIn   time.Time `json:"signed_in"`
}

// session is the command line's stored account key and instance sign-ins.
type session struct {
	AccountKey string                     `json:"account_key,omitempty"`
	Instances  map[string]InstanceSession `json:"instances"`
}

// configurationDirectory returns the directory holding the stored session.
func (a *Args) configurationDirectory() (string, error) {
	if a.ConfigurationDirectory != "" {
		return a.ConfigurationDirectory, nil
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, a.Name), nil
}

// accountKeyEnvironment names the environment variable that supplies an account key.
func (a *Args) accountKeyEnvironment() string {
	return strings.ToUpper(strings.ReplaceAll(a.Name, "-", "_")) + "_ACCOUNT_KEY"
}

// terminalAuthPath returns the instance mount point for terminal authentication.
func (a *Args) terminalAuthPath() string {
	if a.TerminalAuthPath == "" {
		return sdk.DefaultTerminalAuthPath
	}
	return "/" + strings.Trim(a.TerminalAuthPath, "/") + "/"
}

// httpClient returns a copy of the configured client, or one with a request
// timeout, that never follows redirects: every request the CLI sends carries
// an account key, an identity token, or sign-in state.
func (a *Args) httpClient() *http.Client {
	client := &http.Client{Timeout: requestTimeout}
	if a.HTTPClient != nil {
		*client = *a.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// loadSession reads the stored session, returning an empty one when none exists.
func (a *Args) loadSession() (*session, error) {
	directory, err := a.configurationDirectory()
	if err != nil {
		return nil, err
	}
	stored := &session{Instances: map[string]InstanceSession{}}
	content, err := os.ReadFile(filepath.Join(directory, sessionFilename))
	if errors.Is(err, os.ErrNotExist) {
		return stored, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, stored); err != nil {
		return nil, err
	}
	if stored.Instances == nil {
		stored.Instances = map[string]InstanceSession{}
	}
	return stored, nil
}

// saveSession writes the session privately and atomically.
func (a *Args) saveSession(stored *session) error {
	directory, err := a.configurationDirectory()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, sessionDirectoryMode); err != nil {
		return err
	}
	content, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(directory, sessionFilename), content, sessionFileMode)
}

// LoadInstanceSession returns the stored sign-in to an instance, for application commands that
// call the instance with its token. It returns os.ErrNotExist when the command line is not signed in.
func LoadInstanceSession(args *Args, instanceID string) (*InstanceSession, error) {
	stored, err := args.loadSession()
	if err != nil {
		return nil, err
	}
	instance, exists := stored.Instances[instanceID]
	if !exists {
		return nil, os.ErrNotExist
	}
	return &instance, nil
}

// accountKey returns the account key from the flag, the environment or the stored session.
func (a *Args) accountKey(cmd *cobra.Command) (string, error) {
	if flag := cmd.Flags().Lookup(flagKey); flag != nil {
		if key := strings.TrimSpace(flag.Value.String()); key != "" {
			return key, nil
		}
	}
	if key := strings.TrimSpace(os.Getenv(a.accountKeyEnvironment())); key != "" {
		return key, nil
	}
	stored, err := a.loadSession()
	if err != nil {
		return "", err
	}
	return stored.AccountKey, nil
}

// accountClientWithKey returns an Account API client for a known key.
func accountClientWithKey(args *Args, key string) (*account.Client, error) {
	return account.NewClient(&account.NewClientArgs{
		APIOrigin:  args.APIOrigin,
		Key:        key,
		HTTPClient: args.httpClient(),
	})
}

// accountClient returns an Account API client with the account key, or an error naming the next command.
func (a *Args) accountClient(cmd *cobra.Command) (*account.Client, error) {
	key, err := a.accountKey(cmd)
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, fmt.Errorf("no account key. Run %s account login --key ACCOUNT_KEY or set %s", a.Name, a.accountKeyEnvironment())
	}
	return account.NewClient(&account.NewClientArgs{
		APIOrigin:  a.APIOrigin,
		Key:        key,
		HTTPClient: a.httpClient(),
	})
}

// openBrowser opens an address in the user's browser. Failures are reported but never fatal,
// because every caller also prints the address.
func (a *Args) openBrowser(cmd *cobra.Command, address string) {
	if noBrowser, err := cmd.Flags().GetBool(flagNoBrowser); err == nil && noBrowser {
		return
	}
	opener := a.OpenBrowser
	if opener == nil {
		opener = openSystemBrowser
	}
	if err := opener(cmd.Context(), address); err != nil {
		if writeErr := browserNotice(cmd, address); writeErr != nil {
			// Stderr is unavailable; the address was printed to stdout too.
			return
		}
	}
}

// openSystemBrowser starts the platform's URL opener without waiting for the browser.
func openSystemBrowser(ctx context.Context, address string) error {
	executable := ""
	switch runtime.GOOS {
	case "darwin":
		executable = "open"
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no display")
		}
		executable = "xdg-open"
	default:
		return errors.New("unsupported platform")
	}
	command := exec.CommandContext(ctx, executable, address)
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

// field is one named value in an output record.
type field struct {
	name  string
	value any
}

// record is an ordered output record.
type record []field

// addFormatFlag adds --stdout-format to a command.
func addFormatFlag(command *cobra.Command, args *Args) { configurePresentation(command, args) }

// writeRecords renders records as logfmt with an event= leader, JSON lines or one JSON document.
func writeRecords(cmd *cobra.Command, event string, records []record) error {
	presentation := commandPresentation(cmd)
	if presentation != nil && presentation.Results != nil {
		ordered := make([][]ResultField, len(records))
		for i, current := range records {
			for _, field := range current {
				ordered[i] = append(ordered[i], ResultField{Name: field.name, Value: field.value})
			}
		}
		return presentation.Results(cmd, event, ordered)
	}
	format, err := cmd.Flags().GetString(flagStdoutFormat)
	if err != nil {
		format = formatText
	}
	output := cmd.OutOrStdout()
	switch format {
	case formatText:
		for _, current := range records {
			if err := writeLogfmt(output, event, current); err != nil {
				return err
			}
		}
		return nil
	case formatJSONL:
		encoder := json.NewEncoder(output)
		for _, current := range records {
			if err := encoder.Encode(recordObject(event, current)); err != nil {
				return err
			}
		}
		return nil
	case formatJSON:
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if len(records) == 1 {
			return encoder.Encode(recordObject(event, records[0]))
		}
		objects := make([]map[string]any, 0, len(records))
		for _, current := range records {
			objects = append(objects, recordObject(event, current))
		}
		return encoder.Encode(objects)
	default:
		return fmt.Errorf("--stdout-format must be text, jsonl or json, not %q", format)
	}
}

// recordObject converts a record to a JSON object with its event.
func recordObject(event string, current record) map[string]any {
	object := map[string]any{"event": event}
	for _, entry := range current {
		object[entry.name] = entry.value
	}
	return object
}

// writeLogfmt writes one logfmt line, quoting values that need it.
func writeLogfmt(output io.Writer, event string, current record) error {
	parts := []string{"event=" + event}
	for _, entry := range current {
		value := ""
		switch typed := entry.value.(type) {
		case nil:
		case string:
			value = typed
		case bool:
			value = strconv.FormatBool(typed)
		case time.Time:
			value = typed.UTC().Format(time.RFC3339)
		case *time.Time:
			if typed != nil {
				value = typed.UTC().Format(time.RFC3339)
			}
		default:
			value = fmt.Sprint(typed)
		}
		if value == "" || strings.ContainsAny(value, " \"=\t") {
			value = strconv.Quote(value)
		}
		parts = append(parts, entry.name+"="+value)
	}
	_, err := fmt.Fprintln(output, strings.Join(parts, " "))
	return err
}

// resolveInstance finds an instance by ID, name or hostname among the account's instances.
func resolveInstance(ctx context.Context, client *account.Client, reference string) (*account.InstanceSummary, error) {
	reference = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reference), "https://")))
	reference = strings.TrimRight(reference, "/")
	instances, err := client.ListInstances(ctx, nil)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(instances, func(instance account.InstanceSummary) bool {
		return instance.ID == reference || instance.Name == reference || instance.Hostname == reference
	})
	if index < 0 {
		return nil, fmt.Errorf("no instance named %q. List them with instance list", reference)
	}
	return &instances[index], nil
}

// waitForReady polls an instance until it is ready, printing each newly completed step.
func waitForReady(cmd *cobra.Command, client *account.Client, instanceID string) (*account.Instance, error) {
	timeout, err := cmd.Flags().GetDuration(flagTimeout)
	if err != nil || timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	reported := map[string]bool{}
	for {
		instance, err := client.ShowInstance(ctx, instanceID)
		if err != nil {
			return nil, err
		}
		for _, step := range []struct {
			name string
			done bool
		}{
			{"claimed", instance.Readiness.Claimed},
			{"hostname_ready", instance.Readiness.HostnameReady},
			{"certificate_installed", instance.Readiness.CertificateInstalled},
			{"connected", instance.Readiness.Connected},
		} {
			if step.done && !reported[step.name] {
				reported[step.name] = true
				if err := writeProgress(cmd, instanceID, step.name); err != nil {
					return nil, err
				}
			}
		}
		if instance.Readiness.Ready {
			return instance, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("instance %s was not ready within %s. Check it with instance show %s", instanceID, timeout, instanceID)
		case <-time.After(readinessPollInterval):
		}
	}
}

// postJSON sends a JSON request to an instance and decodes a bounded JSON reply.
func postJSON(ctx context.Context, client *http.Client, address string, request, reply any) error {
	content, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(string(content)))
	if err != nil {
		return err
	}
	req.Header.Set(model.HeaderContentType, model.JSONMediaType)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("sign-in failed with status %d. %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, reply)
}
