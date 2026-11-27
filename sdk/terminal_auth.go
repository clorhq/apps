package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	otter "github.com/maypok86/otter/v2"

	"github.com/clorhq/apps/identity"
	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/security"
)

// DefaultTerminalAuthPath is the instance mount point used by the embedded CLI.
const DefaultTerminalAuthPath = "/terminal/auth/"

// Terminal authentication operations are the last path segment under the handler's mount point.
const (
	TerminalAuthDevice   = "device"
	TerminalAuthPoll     = "poll"
	TerminalAuthNonce    = "nonce"
	TerminalAuthExchange = "exchange"
)

// Terminal authentication statuses returned by poll and exchange.
const (
	TerminalAuthPending  = "pending"
	TerminalAuthApproved = "approved"
	TerminalAuthDenied   = "denied"
	TerminalAuthExpired  = "expired"
)

// terminalAuthStateName binds sealed sign-in state to this purpose.
const terminalAuthStateName = "terminal-auth"

// maximumUsedTerminalAuthNonces bounds the unexpired spent nonces remembered;
// past it, new terminal sign-ins are refused until older ones expire.
const maximumUsedTerminalAuthNonces = 10_000

// maximumTerminalAuthRequestBytes bounds terminal authentication request bodies.
const maximumTerminalAuthRequestBytes = 16 * 1024

// TerminalAuthArgs configures how the application issues a token for a verified terminal user.
type TerminalAuthArgs struct {
	IssueToken func(ctx context.Context, user User) (string, error)
}

// TerminalAuthStart is returned by the device and nonce operations.
type TerminalAuthStart struct {
	// State is opaque sealed state to send back with poll or exchange.
	State string `json:"state"`
	// ApprovalURL is the website page where the user approves a device sign-in.
	ApprovalURL string `json:"approval_url,omitempty"`
	// Interval is the minimum number of seconds between polls.
	Interval  int `json:"interval,omitempty"`
	ExpiresIn int `json:"expires_in"`
	// InstanceID and Nonce are the audience and nonce for an account key exchange.
	InstanceID string `json:"instance_id,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

// TerminalAuthRequest is the body of poll and exchange.
type TerminalAuthRequest struct {
	State   string `json:"state"`
	IDToken string `json:"id_token,omitempty"`
}

// TerminalAuthResult is the outcome of poll and exchange. Token and User are set once approved.
type TerminalAuthResult struct {
	Status string `json:"status"`
	Token  string `json:"token,omitempty"`
	User   *User  `json:"user,omitempty"`
}

// terminalAuthState is the sealed state the command line returns with each step.
type terminalAuthState struct {
	DeviceCode string    `json:"device_code,omitempty"`
	Nonce      string    `json:"nonce"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
}

// TerminalAuthHandler serves device approval and account key exchange at the instance mount point.
// Device starts a browser approval and poll checks its status. Nonce starts an account key
// exchange with Apps, and exchange verifies the resulting identity token.
func (c *Client) TerminalAuthHandler(args *TerminalAuthArgs) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		configuration := c.Snapshot()
		if !c.authentication || args == nil || args.IssueToken == nil || !authorizedHostname(configuration, req.Host) {
			http.Error(w, "terminal authentication is unavailable", http.StatusNotFound)
			return
		}
		var request TerminalAuthRequest
		body, err := io.ReadAll(io.LimitReader(req.Body, maximumTerminalAuthRequestBytes+1))
		if err != nil || len(body) > maximumTerminalAuthRequestBytes {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &request); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
		ctx := req.Context()
		switch path.Base(req.URL.Path) {
		case TerminalAuthDevice:
			start, err := c.startDeviceAuth(ctx, configuration, req.Host)
			writeTerminalAuthResponse(w, start, err)
		case TerminalAuthNonce:
			start, err := c.startKeyAuth(configuration, req.Host)
			writeTerminalAuthResponse(w, start, err)
		case TerminalAuthPoll:
			result, err := c.pollDeviceAuth(ctx, configuration, req.Host, &request, args)
			writeTerminalAuthResponse(w, result, err)
		case TerminalAuthExchange:
			result, err := c.exchangeKeyAuth(ctx, configuration, req.Host, &request, args)
			writeTerminalAuthResponse(w, result, err)
		default:
			http.NotFound(w, req)
		}
	})
}

// writeTerminalAuthResponse writes a JSON result, or a generic failure without internal details.
func writeTerminalAuthResponse(w http.ResponseWriter, document any, err error) {
	if errors.Is(err, ErrUnauthenticated) {
		http.Error(w, "sign-in verification failed", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set(model.HeaderContentType, model.JSONMediaType)
	w.Header().Set(model.HeaderCacheControl, "no-store")
	if err := json.NewEncoder(w).Encode(document); err != nil {
		// The client disconnected; it starts a new sign-in.
		return
	}
}

// sealTerminalAuthState seals terminal authentication state for the serving hostname.
func sealTerminalAuthState(configuration *Configuration, hostname string, state *terminalAuthState) (string, error) {
	return sealCookie(configuration, hostname, terminalAuthStateName, state)
}

// openTerminalAuthState opens unexpired terminal authentication state for the serving hostname.
func openTerminalAuthState(configuration *Configuration, hostname, sealed string) (*terminalAuthState, error) {
	var state terminalAuthState
	if err := openSealed(configuration, hostname, terminalAuthStateName, sealed, &state); err != nil {
		return nil, ErrUnauthenticated
	}
	if state.Nonce == "" || !validWindow(state.Issued, state.Expires, time.Now(), terminalAuthTransactionLifetime) {
		return nil, ErrUnauthenticated
	}
	return &state, nil
}

// startDeviceAuth asks Apps for a device authorization and returns its approval URL with sealed state.
func (c *Client) startDeviceAuth(ctx context.Context, configuration *Configuration, hostname string) (*TerminalAuthStart, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	nonce := security.Token()
	var device struct {
		DeviceCode      string `json:"device_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	parameters := url.Values{
		"client_id":     {c.instanceID},
		"client_secret": {c.apiKey},
		"nonce":         {nonce},
	}
	if err := c.identityJSON(ctx, http.MethodPost, c.serviceOrigin+model.RouteIdentityDevice, strings.NewReader(parameters.Encode()), &device); err != nil {
		return nil, err
	}
	approval, err := url.Parse(device.VerificationURI)
	if err != nil || approval.Scheme+"://"+approval.Host != configuration.WebsiteOrigin || device.DeviceCode == "" {
		return nil, errors.New("invalid device authorization")
	}
	now := time.Now()
	lifetime := min(time.Duration(device.ExpiresIn)*time.Second, terminalAuthTransactionLifetime)
	sealed, err := sealTerminalAuthState(configuration, hostname, &terminalAuthState{
		DeviceCode: device.DeviceCode,
		Nonce:      nonce,
		Issued:     now,
		Expires:    now.Add(lifetime),
	})
	if err != nil {
		return nil, err
	}
	return &TerminalAuthStart{
		State:       sealed,
		ApprovalURL: approval.String(),
		Interval:    max(device.Interval, 1),
		ExpiresIn:   int(lifetime / time.Second),
	}, nil
}

// startKeyAuth returns a fresh nonce and the instance audience for an account key exchange.
func (c *Client) startKeyAuth(configuration *Configuration, hostname string) (*TerminalAuthStart, error) {
	now := time.Now()
	nonce := security.Token()
	sealed, err := sealTerminalAuthState(configuration, hostname, &terminalAuthState{
		Nonce:   nonce,
		Issued:  now,
		Expires: now.Add(terminalAuthTransactionLifetime),
	})
	if err != nil {
		return nil, err
	}
	return &TerminalAuthStart{
		State:      sealed,
		ExpiresIn:  int(terminalAuthTransactionLifetime / time.Second),
		InstanceID: c.instanceID,
		Nonce:      nonce,
	}, nil
}

// pollDeviceAuth checks the device authorization once and issues the application token when approved.
func (c *Client) pollDeviceAuth(
	ctx context.Context,
	configuration *Configuration,
	hostname string,
	request *TerminalAuthRequest,
	args *TerminalAuthArgs,
) (*TerminalAuthResult, error) {
	state, err := openTerminalAuthState(configuration, hostname, request.State)
	if err != nil || state.DeviceCode == "" {
		return nil, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	metadata, err := c.identityCache.Get(ctx, configuration.WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
	if err != nil {
		return nil, err
	}
	parameters := url.Values{
		"grant_type":    {model.OAuthDeviceCodeGrant},
		"client_id":     {c.instanceID},
		"client_secret": {c.apiKey},
		"device_code":   {state.DeviceCode},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.Discovery.TokenEndpoint, strings.NewReader(parameters.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set(model.HeaderContentType, model.FormMediaType)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("identity request failed")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil || len(encoded) > model.MaximumJSONSize {
		return nil, errors.New("identity response read failed")
	}
	var token struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(encoded, &token); err != nil {
		return nil, errors.New("invalid identity response")
	}
	switch {
	case res.StatusCode == http.StatusBadRequest && token.Error == model.OAuthAuthorizationPending:
		return &TerminalAuthResult{Status: TerminalAuthPending}, nil
	case res.StatusCode == http.StatusBadRequest && token.Error == model.OAuthAccessDenied:
		return &TerminalAuthResult{Status: TerminalAuthDenied}, nil
	case res.StatusCode == http.StatusBadRequest:
		return &TerminalAuthResult{Status: TerminalAuthExpired}, nil
	case res.StatusCode != http.StatusOK:
		return nil, errors.New("identity request rejected")
	}
	claims, err := c.verifyIdentityToken(ctx, metadata, token.IDToken, state.Nonce)
	if err != nil {
		return nil, err
	}
	return c.completeTerminalAuth(ctx, state, claims, args)
}

// exchangeKeyAuth verifies an identity token the command line obtained with an account key.
func (c *Client) exchangeKeyAuth(
	ctx context.Context,
	configuration *Configuration,
	hostname string,
	request *TerminalAuthRequest,
	args *TerminalAuthArgs,
) (*TerminalAuthResult, error) {
	state, err := openTerminalAuthState(configuration, hostname, request.State)
	if err != nil || state.DeviceCode != "" || request.IDToken == "" {
		return nil, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	metadata, err := c.identityCache.Get(ctx, configuration.WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
	if err != nil {
		return nil, err
	}
	claims, err := c.verifyIdentityToken(ctx, metadata, request.IDToken, state.Nonce)
	if err != nil {
		return nil, err
	}
	return c.completeTerminalAuth(ctx, state, claims, args)
}

// completeTerminalAuth spends the nonce once and asks the application to issue its token.
func (c *Client) completeTerminalAuth(
	ctx context.Context,
	state *terminalAuthState,
	claims *identity.Claims,
	args *TerminalAuthArgs,
) (*TerminalAuthResult, error) {
	unspent, err := c.usedTerminalAuthNonces.Spend(ctx, state.Nonce, state.Expires)
	if err != nil {
		return nil, err
	}
	if !unspent {
		return nil, ErrUnauthenticated
	}
	user := User{
		ID:    claims.Subject,
		Email: claims.Email,
		Owner: claims.Owner,
	}
	token, err := args.IssueToken(ctx, user)
	if err != nil {
		return nil, err
	}
	return &TerminalAuthResult{
		Status: TerminalAuthApproved,
		Token:  token,
		User:   &user,
	}, nil
}
