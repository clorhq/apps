// Package sdk provides optional application configuration, TLS, licensing and local authentication.
package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	otter "github.com/maypok86/otter/v2"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"

	"github.com/clorhq/apps/license"
	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/security"
)

const (
	DefaultSessionLifetime          = model.DefaultBrowserSessionLifetime
	SignInTransactionLifetime       = model.BrowserAuthorizationLifetime
	terminalAuthTransactionLifetime = 5 * time.Minute
	configurationInterval           = time.Hour
	requestTimeout                  = 15 * time.Second
	maximumBackoff                  = 5 * time.Minute
)

var ErrIncompleteConfiguration = errors.New("required application configuration is unavailable")

var ErrLicenseVerificationUnavailable = errors.New("license verification requires application-supplied trust roots")

// Configuration is the documented, versioned application-facing HTTP contract.
type Configuration = model.ApplicationConfiguration

// NewClientArgs supplies bootstrap overrides and declares the capabilities the application requires.
type NewClientArgs struct {
	TrustedLicenseKeys map[string]string
	Configuration      *Configuration
	AppID              string
	InstanceID         string
	ServiceOrigin      string
	WebsiteOrigin      string
	APIKey             string
	EnvironmentOnly    bool
	Authentication     bool
	RequireLicense     bool
	RequireTLS         bool
	SessionLifetime    time.Duration
	HTTPClient         *http.Client
	Logger             *slog.Logger
	// CertificateCacheDirectory stores certificates the SDK obtains through ACME for the
	// instance's custom domains. Without it, custom domains get no certificate.
	CertificateCacheDirectory string
	// ACMEDirectoryURL selects the ACME server for custom domains, Let's Encrypt by default.
	ACMEDirectoryURL string
	// SpentNonces records the terminal sign-in nonces already exchanged. Nil
	// keeps them in this process's memory, which a restart forgets and other
	// replicas of the instance do not share: within a sign-in's 5-minute
	// lifetime, a used sign-in could then be exchanged again after a restart or
	// on another replica. An app that runs replicas, or wants that closed,
	// passes a store every process shares.
	SpentNonces SpentNonceStore
}

// Status reports refresh health without retaining server error bodies or credentials.
type Status struct {
	Stopped   bool
	Attempted time.Time
	Succeeded time.Time
	Next      time.Time
	Error     string
}

// Client owns immutable validated snapshots and its bounded background refresh lifecycle.
type Client struct {
	accessKeyRefresh *rate.Limiter
	certificate      *tls.Certificate
	licenseKeys      map[string]ed25519.PublicKey
	identityCache    *otter.Cache[string, *identityMetadata]
	// usedTerminalAuthNonces makes each terminal authentication nonce single use within its lifetime.
	usedTerminalAuthNonces                     SpentNonceStore
	mutex                                      sync.RWMutex
	configuration                              *Configuration
	status                                     Status
	etag                                       string
	appID, instanceID, serviceOrigin, apiKey   string
	authentication, requireLicense, requireTLS bool
	sessionLifetime                            time.Duration
	client                                     *http.Client
	logger                                     *slog.Logger
	cancel                                     context.CancelFunc
	workers                                    sync.WaitGroup
	// customCertificates obtains certificates for custom domains, or nil without a cache directory.
	customCertificates *autocert.Manager
}

// NewClient starts from explicit or managed environment configuration and fetches missing requirements once.
func NewClient(ctx context.Context, args *NewClientArgs) (*Client, error) {
	if args == nil {
		args = &NewClientArgs{}
	}
	var configuration *Configuration
	var apiKey string
	var err error
	if args.Configuration != nil {
		configuration = cloneConfiguration(args.Configuration)
	} else {
		configuration, apiKey, err = LoadEnvironment()
		if err != nil {
			return nil, err
		}
	}
	for _, override := range []struct {
		value  string
		target *string
	}{
		{args.AppID, &configuration.AppID},
		{args.InstanceID, &configuration.InstanceID},
		{args.ServiceOrigin, &configuration.ServiceOrigin},
		{args.WebsiteOrigin, &configuration.WebsiteOrigin},
		{args.APIKey, &apiKey},
	} {
		if override.value != "" {
			*override.target = strings.TrimSpace(override.value)
		}
	}
	if configuration.Version == 0 {
		configuration.Version = model.ProtocolVersion
	}
	if configuration.AuthCallbackPath == "" {
		configuration.AuthCallbackPath = model.DefaultAuthCallbackPath
	}
	if configuration.AuthSignInPath == "" {
		configuration.AuthSignInPath = model.DefaultAuthSignInPath
	}
	if apiKey != "" && (len(apiKey) < 32 || len(apiKey) > 256 || strings.ContainsAny(apiKey, "\r\n")) {
		return nil, errors.New("invalid instance API key")
	}
	if configuration.ServiceOrigin != "" && !validOrigin(configuration.ServiceOrigin) {
		return nil, errors.New("service origin must be an exact HTTPS origin")
	}
	if configuration.AppID == "" || configuration.InstanceID == "" ||
		strings.ContainsAny(configuration.AppID+configuration.InstanceID, "/?#\\\r\n") {
		return nil, errors.New("app and instance identifiers are required")
	}
	lifetime := args.SessionLifetime
	if lifetime == 0 {
		lifetime = DefaultSessionLifetime
	}
	if lifetime < time.Second || lifetime > 365*24*time.Hour {
		return nil, errors.New("session lifetime must be between one second and one year")
	}
	httpClient := &http.Client{}
	if args.HTTPClient != nil {
		*httpClient = *args.HTTPClient
	}
	httpClient.Timeout = requestTimeout
	httpClient.CheckRedirect = rejectRedirect
	logger := args.Logger
	if logger == nil {
		logger = slog.Default()
	}
	client := &Client{
		accessKeyRefresh: rate.NewLimiter(rate.Every(time.Minute), 1),
		appID:            configuration.AppID,
		instanceID:       configuration.InstanceID,
		serviceOrigin:    configuration.ServiceOrigin,
		apiKey:           apiKey,
		authentication:   args.Authentication,
		requireLicense:   args.RequireLicense,
		requireTLS:       args.RequireTLS,
		sessionLifetime:  lifetime,
		client:           httpClient,
		logger:           logger,
	}
	if directory := strings.TrimSpace(args.CertificateCacheDirectory); directory != "" {
		client.customCertificates = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(directory),
			HostPolicy: client.customDomainPolicy,
		}
		if args.ACMEDirectoryURL != "" {
			client.customCertificates.Client = &acme.Client{DirectoryURL: args.ACMEDirectoryURL}
		}
	}
	client.licenseKeys, err = license.ParseKeys(args.TrustedLicenseKeys)
	if err != nil {
		return nil, err
	}
	if args.RequireLicense && len(client.licenseKeys) == 0 {
		return nil, ErrLicenseVerificationUnavailable
	}
	if args.Authentication && apiKey == "" {
		return nil, errors.New("authentication requires the instance API key")
	}
	validationErr := client.validateConfiguration(configuration)
	if validationErr != nil && !errors.Is(validationErr, ErrIncompleteConfiguration) {
		return nil, validationErr
	}
	networking := !args.EnvironmentOnly
	if networking && (apiKey == "" || configuration.ServiceOrigin == "") {
		return nil, errors.New("network configuration requires service origin and instance API key; select environment-only mode for offline use")
	}
	if validationErr == nil {
		client.licenseKeys, err = client.configurationKeys(configuration)
		if err != nil {
			return nil, err
		}
		client.configuration = cloneConfiguration(configuration)
		client.certificate, err = configurationCertificate(configuration)
		if err != nil {
			return nil, err
		}
	}
	if client.configuration == nil {
		if !networking {
			return nil, ErrIncompleteConfiguration
		}
		if err := client.refreshConfiguration(ctx); err != nil {
			return nil, fmt.Errorf("application startup: %w", err)
		}
	}
	runContext, cancel := context.WithCancel(ctx)
	client.cancel = cancel
	client.identityCache, err = otter.New(&otter.Options[string, *identityMetadata]{
		MaximumSize:      1,
		ExpiryCalculator: otter.ExpiryWriting[string, *identityMetadata](identityCacheLifetime),
	})
	if err != nil {
		cancel()
		return nil, err
	}
	client.usedTerminalAuthNonces = args.SpentNonces
	if client.usedTerminalAuthNonces == nil {
		client.usedTerminalAuthNonces = newSpentNonces(maximumUsedTerminalAuthNonces)
	}
	if networking {
		client.workers.Go(func() { client.refreshLoop(runContext) })
	}
	return client, nil
}

// rejectRedirect prevents configuration and token credentials from following redirects.
func rejectRedirect(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

// validOrigin accepts only canonical HTTPS origins with no path or credentials.
func validOrigin(origin string) bool {
	address, err := url.Parse(origin)
	return err == nil &&
		address.Scheme == "https" &&
		address.Host != "" &&
		address.User == nil &&
		address.Path == "" &&
		address.RawQuery == "" &&
		!address.ForceQuery &&
		address.Fragment == "" &&
		address.RawPath == "" &&
		address.String() == origin
}

// cloneConfiguration prevents callers from changing the published snapshot or its collections.
func cloneConfiguration(configuration *Configuration) *Configuration {
	copied := *configuration
	copied.Aliases = slices.Clone(configuration.Aliases)
	copied.CustomDomains = slices.Clone(configuration.CustomDomains)
	copied.AuthProviders = slices.Clone(configuration.AuthProviders)
	copied.Values = maps.Clone(configuration.Values)
	copied.VerificationKeys = maps.Clone(configuration.VerificationKeys)
	copied.VerificationKeySets = slices.Clone(configuration.VerificationKeySets)
	if configuration.License != nil {
		document := *configuration.License
		copied.License = &document
	}
	if configuration.TLS != nil {
		certificate := *configuration.TLS
		copied.TLS = &certificate
	}
	return &copied
}

// Snapshot returns a detached snapshot safe for application-owned mutation.
func (c *Client) Snapshot() *Configuration {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return cloneConfiguration(c.configuration)
}

// Status returns the last refresh outcome without requiring a network request.
func (c *Client) Status() Status {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.status
}

// Close cancels in-flight refreshes and waits for the client's lifecycle goroutine.
func (c *Client) Close() error {
	c.cancel()
	c.workers.Wait()
	c.identityCache.StopAllGoroutines()
	c.mutex.Lock()
	c.status.Stopped = true
	c.status.Next = time.Time{}
	c.mutex.Unlock()
	return nil
}

// validateConfiguration checks every supplied capability before atomically publishing a snapshot.
func (c *Client) validateConfiguration(configuration *Configuration) error {
	if configuration.Version != model.ProtocolVersion ||
		configuration.AppID != c.appID ||
		configuration.InstanceID != c.instanceID ||
		configuration.ServiceOrigin != c.serviceOrigin {
		return errors.New("configuration version or audience mismatch")
	}
	if err := model.ValidateAuthPaths(configuration.AuthSignInPath, configuration.AuthCallbackPath); err != nil {
		return err
	}
	if configuration.WebsiteOrigin != "" && !validOrigin(configuration.WebsiteOrigin) {
		return errors.New("website origin must be an exact HTTPS origin")
	}
	if err := model.ValidateEnvironment(configuration.Values); err != nil {
		return err
	}
	for _, hostname := range append(slices.Clone(configuration.Aliases), configuration.PrimaryHostname) {
		if hostname != "" && !validHostname(hostname) {
			return errors.New("invalid authorized hostname")
		}
	}
	for _, provider := range configuration.AuthProviders {
		if provider != model.ProviderGoogle && provider != model.ProviderGitHub {
			return errors.New("unsupported sign-in provider")
		}
	}
	if configuration.CookieKey != "" {
		key, err := base64.StdEncoding.DecodeString(configuration.CookieKey)
		if err != nil || len(key) != security.EncryptionKeySize {
			return errors.New("invalid cookie encryption key")
		}
	}
	keys, err := c.configurationKeys(configuration)
	if err != nil {
		return err
	}
	if configuration.License != nil && len(keys) > 0 {
		if _, err := license.VerifyLicense(configuration.License, keys, c.appID, c.instanceID, time.Now()); err != nil {
			return errors.New("invalid signed application license")
		}
	}
	if configuration.TLS != nil {
		pair, err := tls.X509KeyPair([]byte(configuration.TLS.Certificate), []byte(configuration.TLS.PrivateKey))
		if err != nil || pair.Leaf.NotAfter.Unix() != configuration.TLS.Expires.Unix() {
			return errors.New("invalid TLS certificate bundle")
		}
		for _, hostname := range append(slices.Clone(configuration.Aliases), configuration.PrimaryHostname) {
			if hostname != "" {
				if err := pair.Leaf.VerifyHostname(hostname); err != nil {
					return errors.New("TLS certificate does not cover authorized hostname")
				}
			}
		}
	}
	if c.authentication &&
		(configuration.CookieKey == "" ||
			configuration.PrimaryHostname == "" && len(configuration.CustomDomains) == 0 ||
			configuration.ServiceOrigin == "" ||
			configuration.WebsiteOrigin == "") ||
		c.requireLicense && configuration.License == nil ||
		// Custom domains with ACME certificates keep serving while the Apps certificate is unavailable.
		c.requireTLS && configuration.TLS == nil && (len(configuration.CustomDomains) == 0 || c.customCertificates == nil) {
		return ErrIncompleteConfiguration
	}
	return nil
}

// validHostname excludes ports, paths, ambiguous labels and request-controlled URL syntax.
func validHostname(hostname string) bool {
	if len(hostname) > 253 || hostname != strings.ToLower(hostname) {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

// configurationKeys admits rotation only through application-pinned trust.
func (c *Client) configurationKeys(configuration *Configuration) (map[string]ed25519.PublicKey, error) {
	c.mutex.RLock()
	trusted := maps.Clone(c.licenseKeys)
	c.mutex.RUnlock()
	if len(trusted) == 0 {
		return trusted, nil
	}
	if _, err := license.ParseKeys(configuration.VerificationKeys); err != nil {
		return nil, err
	}
	return license.AdmitKeys(trusted, configuration.VerificationKeySets, c.appID)
}

// refreshConfiguration validates a bounded authenticated response before replacing the active snapshot.
func (c *Client) refreshConfiguration(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	c.mutex.Lock()
	c.status.Attempted = time.Now()
	etag := c.etag
	c.mutex.Unlock()
	endpoint := c.serviceOrigin + model.InstanceAPIPrefix + url.PathEscape(c.instanceID) + model.ApplicationConfigurationRoute
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid configuration request")
	}
	req.Header.Set(model.HeaderAuthorization, model.BearerPrefix+c.apiKey)
	req.Header.Set(model.HeaderIfNoneMatch, etag)
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("configuration request failed")
	}
	content, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil {
		return errors.New("configuration response read failed")
	}
	if res.StatusCode == http.StatusNotModified && etag != "" {
		c.mutex.Lock()
		c.status.Succeeded = time.Now()
		c.status.Error = ""
		c.mutex.Unlock()
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("configuration request returned HTTP %d", res.StatusCode)
	}
	if len(content) > model.MaximumJSONSize {
		return errors.New("configuration response exceeds size limit")
	}
	var configuration Configuration
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return errors.New("invalid configuration document")
	}
	for _, name := range []string{
		"version",
		"app_id",
		"instance_id",
		"service_origin",
		"website_origin",
		"auth_signin_path",
		"primary_hostname",
		"aliases",
		"auth_callback_path",
		"auth_providers",
		"cookie_key",
		"license",
		"verification_keys",
		"tls",
		"values",
	} {
		if _, exists := fields[name]; !exists {
			return errors.New("incomplete configuration response")
		}
	}
	if err := json.Unmarshal(content, &configuration); err != nil {
		return errors.New("invalid configuration document")
	}
	if err := c.validateConfiguration(&configuration); err != nil {
		return err
	}
	keys, err := c.configurationKeys(&configuration)
	if err != nil {
		return err
	}
	certificate, err := configurationCertificate(&configuration)
	if err != nil {
		return err
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Cookie keys are durable; an API-key update must never replace local session authority.
	if c.configuration != nil && c.configuration.CookieKey != "" &&
		c.configuration.CookieKey != configuration.CookieKey {
		return errors.New("instance cookie key changed unexpectedly")
	}
	c.configuration = cloneConfiguration(&configuration)
	c.certificate = certificate
	c.licenseKeys = keys
	c.etag = res.Header.Get(model.HeaderETag)
	c.status.Succeeded = time.Now()
	c.status.Error = ""
	return nil
}

// refreshLoop refreshes asynchronously with hourly jitter and bounded exponential failure retries.
func (c *Client) refreshLoop(ctx context.Context) {
	defer func() {
		c.mutex.Lock()
		c.status.Stopped = true
		c.status.Next = time.Time{}
		c.mutex.Unlock()
	}()
	backoff := time.Second
	startupFetched := !c.Status().Succeeded.IsZero()
	for {
		var err error
		if !startupFetched {
			err = c.refreshConfiguration(ctx)
		}
		startupFetched = false
		if ctx.Err() != nil {
			return
		}
		delay := configurationInterval + time.Duration(mathrand.Int64N(int64(12*time.Minute))) - 6*time.Minute
		if err != nil {
			c.logger.Warn("application configuration refresh failed", "error", err)
			delay = backoff + time.Duration(mathrand.Int64N(int64(backoff/4+1)))
			backoff = min(backoff*2, maximumBackoff*4/5)
		} else {
			backoff = time.Second
		}
		c.mutex.Lock()
		if err != nil {
			c.status.Error = err.Error()
		}
		c.status.Next = time.Now().Add(delay)
		c.mutex.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
