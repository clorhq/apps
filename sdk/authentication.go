package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	otter "github.com/maypok86/otter/v2"

	"github.com/clorhq/apps/identity"
	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/security"
)

const (
	SessionCookieName           = "__Host-application_session"
	SignInTransactionCookieName = "__Host-application_signin"
	CSRFHeader                  = "X-CSRF-Token"
	maximumCookieCharacters     = 3_800
	identityCacheLifetime       = 5 * time.Minute
)

var ErrUnauthenticated = errors.New("application authentication required")

// User is the stable app identity and verified email proved during sign-in. Owner is true when
// the user is an admin of the instance's team at sign-in. The session retains that value until the next sign-in.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Owner bool   `json:"owner"`
}

type localSession struct {
	AppID      string    `json:"app_id"`
	InstanceID string    `json:"instance_id"`
	User       User      `json:"user"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
	CSRF       string    `json:"csrf"`
}

type signInTransaction struct {
	State      string    `json:"state"`
	Verifier   string    `json:"verifier"`
	Nonce      string    `json:"nonce"`
	Callback   string    `json:"callback"`
	ReturnPath string    `json:"return_path"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
}

type sessionContextKey struct{}

// UserFromContext returns the identity installed by optional or required authentication middleware.
func UserFromContext(ctx context.Context) (User, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(*localSession)
	if !ok {
		return User{}, false
	}
	return session.User, true
}

// CSRFToken returns the session token for non-browser clients that cannot send an Origin header.
func CSRFToken(ctx context.Context) string {
	session, ok := ctx.Value(sessionContextKey{}).(*localSession)
	if !ok {
		return ""
	}
	return session.CSRF
}

// SignInArgs selects a server-authorized hostname and a local post-authentication destination.
type SignInArgs struct {
	Hostname   string
	ReturnPath string
}

// SignInHandler initiates browser-bound state, S256 PKCE and nonce with a five-minute transaction.
func (c *Client) SignInHandler(args *SignInArgs) http.Handler {
	settings := SignInArgs{ReturnPath: "/"}
	if args != nil {
		settings = *args
		if settings.ReturnPath == "" {
			settings.ReturnPath = "/"
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		configuration := c.Snapshot()
		hostname := settings.Hostname
		if hostname == "" {
			hostname = configuration.PrimaryHostname
			// A request on one of the instance's custom domains signs in on that domain.
			if slices.Contains(configuration.CustomDomains, req.Host) {
				hostname = req.Host
			}
		}
		if !c.authentication || !authorizedHostname(configuration, hostname) || req.Host != hostname ||
			!validReturnPath(settings.ReturnPath) {
			http.Error(w, "invalid Sign In destination", http.StatusBadRequest)
			return
		}
		discovery, err := c.discovery(req.Context())
		if err != nil {
			http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
			return
		}
		now := time.Now()
		transaction := signInTransaction{
			State:      security.Token(),
			Verifier:   security.Token(),
			Nonce:      security.Token(),
			Callback:   "https://" + hostname + configuration.AuthCallbackPath,
			ReturnPath: settings.ReturnPath,
			Issued:     now,
			Expires:    now.Add(SignInTransactionLifetime),
		}
		encrypted, err := sealCookie(configuration, hostname, SignInTransactionCookieName, &transaction)
		if err != nil {
			http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
			return
		}
		setCookie(w, SignInTransactionCookieName, encrypted, SignInTransactionLifetime)
		destination, err := url.Parse(discovery.AuthorizationEndpoint)
		if err != nil {
			http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
			return
		}
		digest := sha256.Sum256([]byte(transaction.Verifier))
		query := destination.Query()
		query.Set("response_type", "code")
		query.Set("client_id", c.instanceID)
		query.Set("redirect_uri", transaction.Callback)
		query.Set("scope", "openid email")
		query.Set("state", transaction.State)
		query.Set("nonce", transaction.Nonce)
		query.Set("code_challenge_method", model.IdentityPKCEMethod)
		query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(digest[:]))
		destination.RawQuery = query.Encode()
		http.Redirect(w, req, destination.String(), http.StatusFound)
	})
}

// CallbackHandler validates the complete identity protocol before creating an independent local session.
func (c *Client) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		configuration := c.Snapshot()
		var transaction signInTransaction
		err := openCookie(req, configuration, SignInTransactionCookieName, &transaction)
		setCookie(w, SignInTransactionCookieName, "", -time.Second)
		now := time.Now()
		if !c.authentication || err != nil || transaction.State == "" ||
			subtle.ConstantTimeCompare([]byte(transaction.State), []byte(req.URL.Query().Get("state"))) != 1 ||
			!validWindow(transaction.Issued, transaction.Expires, now, SignInTransactionLifetime) ||
			transaction.Callback != "https://"+req.Host+configuration.AuthCallbackPath ||
			req.URL.Path != configuration.AuthCallbackPath ||
			!validReturnPath(transaction.ReturnPath) {
			http.Error(w, "invalid sign-in transaction", http.StatusUnauthorized)
			return
		}
		if req.URL.Query().Get("error") == model.OAuthAccessDenied && req.URL.Query().Get("code") == "" {
			http.Redirect(w, req, transaction.ReturnPath, http.StatusSeeOther)
			return
		}
		if req.URL.Query().Get("error") != "" || req.URL.Query().Get("code") == "" {
			http.Error(w, "invalid sign-in response", http.StatusUnauthorized)
			return
		}
		claims, err := c.exchangeIdentity(req.Context(), &transaction, req.URL.Query().Get("code"))
		if err != nil || !time.Now().Before(transaction.Expires) {
			http.Error(w, "sign-in verification failed", http.StatusUnauthorized)
			return
		}
		now = time.Now()
		session := &localSession{
			AppID:      c.appID,
			InstanceID: c.instanceID,
			User:       User{ID: claims.Subject, Email: claims.Email, Owner: claims.Owner},
			Issued:     now,
			Expires:    now.Add(c.sessionLifetime),
			CSRF:       security.Token(),
		}
		encrypted, err := sealCookie(configuration, req.Host, SessionCookieName, session)
		if err != nil {
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}
		setCookie(w, SessionCookieName, encrypted, c.sessionLifetime)
		http.Redirect(w, req, transaction.ReturnPath, http.StatusSeeOther)
	})
}

// LogoutHandler clears only the local application cookie after an exact-origin POST.
func (c *Client) LogoutHandler(returnPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		if !validReturnPath(returnPath) {
			http.Error(w, "invalid return path", http.StatusBadRequest)
			return
		}
		if !sameOrigin(req, c.Snapshot()) {
			http.Error(w, "request origin is not allowed", http.StatusForbidden)
			return
		}
		setCookie(w, SessionCookieName, "", -time.Second)
		http.Redirect(w, req, returnPath, http.StatusSeeOther)
	})
}

// OptionalAuthentication attaches a local identity and protects cookie-authenticated unsafe requests from CSRF.
func (c *Client) OptionalAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		session, err := c.readSession(req)
		if err == nil {
			if !safeMethod(req.Method) && !sameOrigin(req, c.Snapshot()) {
				token := req.Header.Get(CSRFHeader)
				if req.Header.Get(model.HeaderOrigin) != "" || token == "" ||
					subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRF)) != 1 {
					http.Error(w, "request origin is not allowed", http.StatusForbidden)
					return
				}
			}
			req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, session))
		}
		next.ServeHTTP(w, req)
	})
}

// RequiredAuthentication returns 401 for unauthenticated API requests without browser redirects.
func (c *Client) RequiredAuthentication(next http.Handler) http.Handler {
	return c.OptionalAuthentication(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := UserFromContext(req.Context()); !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	}))
}

// RequireOwner returns 401 without a signed-in user and 403 unless their session carries the owner claim.
func (c *Client) RequireOwner(next http.Handler) http.Handler {
	return c.RequiredAuthentication(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user, _ := UserFromContext(req.Context())
		if !user.Owner {
			http.Error(w, "only the owner can do this", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, req)
	}))
}

// RequireSignIn explicitly redirects unauthenticated browser GET requests to an application Sign In route.
func (c *Client) RequireSignIn(signInPath string, next http.Handler) http.Handler {
	return c.OptionalAuthentication(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := UserFromContext(req.Context()); !ok {
			if req.Method != http.MethodGet || !validReturnPath(signInPath) {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, req, signInPath, http.StatusFound)
			return
		}
		next.ServeHTTP(w, req)
	}))
}

// readSession authenticates a local cookie without contacting Apps or checking provider session state.
func (c *Client) readSession(req *http.Request) (*localSession, error) {
	var session localSession
	if err := openCookie(req, c.Snapshot(), SessionCookieName, &session); err != nil {
		return nil, ErrUnauthenticated
	}
	if session.AppID != c.appID ||
		session.InstanceID != c.instanceID ||
		session.User.ID == "" ||
		session.User.Email == "" ||
		session.CSRF == "" ||
		!validWindow(session.Issued, session.Expires, time.Now(), 365*24*time.Hour) {
		return nil, ErrUnauthenticated
	}
	return &session, nil
}

// validWindow enforces absolute expiry without sliding renewal.
func validWindow(issued, expires, now time.Time, maximum time.Duration) bool {
	return !issued.IsZero() &&
		!issued.After(now.Add(time.Minute)) &&
		expires.After(issued) &&
		expires.Sub(issued) <= maximum &&
		now.Before(expires)
}

// authorizedHostname checks an exact trusted configuration name, never forwarding headers.
func authorizedHostname(configuration *Configuration, hostname string) bool {
	return hostname != "" &&
		(hostname == configuration.PrimaryHostname ||
			slices.Contains(configuration.Aliases, hostname) ||
			slices.Contains(configuration.CustomDomains, hostname))
}

// sameOrigin requires the browser origin and serving hostname to match trusted configuration exactly.
func sameOrigin(req *http.Request, configuration *Configuration) bool {
	return authorizedHostname(configuration, req.Host) && req.Header.Get(model.HeaderOrigin) == "https://"+req.Host
}

// validReturnPath excludes absolute, scheme-relative and encoded redirect ambiguities.
func validReturnPath(returnPath string) bool {
	return model.ValidReturnPath(returnPath)
}

// safeMethod identifies HTTP methods that do not mutate application state.
func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// sealCookie encrypts a size-bounded document bound to the app, instance, host and cookie purpose.
func sealCookie(configuration *Configuration, hostname, name string, document any) (string, error) {
	key, err := base64.StdEncoding.DecodeString(configuration.CookieKey)
	if err != nil {
		return "", ErrUnauthenticated
	}
	content, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	encrypted, err := security.Seal(key, configuration.AppID+"/"+configuration.InstanceID+"/"+hostname+"/"+name, content)
	if err != nil || len(encrypted) > maximumCookieCharacters {
		return "", errors.New("invalid cookie document")
	}
	return encrypted, nil
}

// openCookie validates the serving host and decrypts a bounded purpose-specific cookie.
func openCookie(req *http.Request, configuration *Configuration, name string, document any) error {
	cookie, err := req.Cookie(name)
	if err != nil {
		return ErrUnauthenticated
	}
	return openSealed(configuration, req.Host, name, cookie.Value, document)
}

// openSealed decrypts a bounded purpose-specific document sealed for an authorized hostname.
func openSealed(configuration *Configuration, hostname, name, sealed string, document any) error {
	if !authorizedHostname(configuration, hostname) || len(sealed) > maximumCookieCharacters {
		return ErrUnauthenticated
	}
	key, err := base64.StdEncoding.DecodeString(configuration.CookieKey)
	if err != nil {
		return ErrUnauthenticated
	}
	content, err := security.Open(key, configuration.AppID+"/"+configuration.InstanceID+"/"+hostname+"/"+name, sealed)
	if err != nil {
		return ErrUnauthenticated
	}
	if err := json.Unmarshal(content, document); err != nil {
		return ErrUnauthenticated
	}
	return nil
}

// setCookie emits secure host-only cookies with absolute expiry and consistent deletion attributes.
func setCookie(w http.ResponseWriter, name, value string, lifetime time.Duration) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     name,
			Value:    value,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(lifetime / time.Second),
			Expires:  time.Now().Add(lifetime),
		},
	)
}

// methodNotAllowed advertises the handler's one supported method.
func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type identityMetadata struct {
	Discovery discoveryDocument
	Keys      map[string]ed25519.PublicKey
}

// discovery uses bounded cached issuer metadata pinned to the configured service origin.
func (c *Client) discovery(ctx context.Context) (*discoveryDocument, error) {
	metadata, err := c.identityCache.Get(ctx, c.Snapshot().WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
	if err != nil {
		return nil, err
	}
	document := metadata.Discovery
	return &document, nil
}

// loadIdentityMetadata verifies discovery endpoints and a bounded Ed25519 JWKS document.
func (c *Client) loadIdentityMetadata(ctx context.Context, websiteOrigin string) (*identityMetadata, error) {
	origin := c.serviceOrigin
	metadata := &identityMetadata{Keys: map[string]ed25519.PublicKey{}}
	if err := c.identityJSON(ctx, http.MethodGet, origin+model.RouteIdentityDiscovery, nil, &metadata.Discovery); err != nil {
		return nil, err
	}
	discovery := &metadata.Discovery
	if discovery.Issuer != origin {
		return nil, errors.New("identity issuer mismatch")
	}
	for _, endpoint := range []struct {
		URL    string
		Origin string
	}{
		{discovery.AuthorizationEndpoint, websiteOrigin},
		{discovery.TokenEndpoint, origin},
		{discovery.JWKSURI, origin},
	} {
		address, err := url.Parse(endpoint.URL)
		if err != nil ||
			address.Scheme+"://"+address.Host != endpoint.Origin ||
			address.User != nil ||
			address.Fragment != "" ||
			address.RawQuery != "" {
			return nil, errors.New("identity endpoint origin mismatch")
		}
	}
	var document struct {
		Keys []struct {
			ID        string `json:"kid"`
			Type      string `json:"kty"`
			Curve     string `json:"crv"`
			Algorithm string `json:"alg"`
			Use       string `json:"use"`
			Key       string `json:"x"`
		} `json:"keys"`
	}
	if err := c.identityJSON(ctx, http.MethodGet, discovery.JWKSURI, nil, &document); err != nil {
		return nil, err
	}
	if len(document.Keys) == 0 || len(document.Keys) > 100 {
		return nil, errors.New("invalid identity verification keys")
	}
	for _, entry := range document.Keys {
		key, err := base64.RawURLEncoding.DecodeString(entry.Key)
		if err != nil || entry.ID == "" || entry.Type != model.IdentityKeyType || entry.Curve != model.IdentityKeyCurve ||
			entry.Algorithm != model.IdentitySigningAlgorithm ||
			entry.Use != "sig" ||
			len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid identity verification key")
		}
		if _, exists := metadata.Keys[entry.ID]; exists {
			return nil, errors.New("duplicate identity verification key")
		}
		metadata.Keys[entry.ID] = key
	}
	return metadata, nil
}

// exchangeIdentity validates issuer, audience, signature, nonce and lifetime after single-use code exchange.
func (c *Client) exchangeIdentity(ctx context.Context, transaction *signInTransaction, code string) (*identity.Claims, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	metadata, err := c.identityCache.Get(ctx, c.Snapshot().WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
	if err != nil {
		return nil, err
	}
	parameters := url.Values{
		"grant_type":    {model.OAuthAuthorizationCode},
		"client_id":     {c.instanceID},
		"client_secret": {c.apiKey},
		"redirect_uri":  {transaction.Callback},
		"code":          {code},
		"code_verifier": {transaction.Verifier},
	}
	var exchanged struct {
		IDToken string `json:"id_token"`
	}
	if err := c.identityJSON(
		ctx,
		http.MethodPost,
		metadata.Discovery.TokenEndpoint,
		strings.NewReader(parameters.Encode()),
		&exchanged,
	); err != nil {
		return nil, err
	}
	return c.verifyIdentityToken(ctx, metadata, exchanged.IDToken, transaction.Nonce)
}

// verifyIdentityToken validates an identity token's signature, issuer, audience, nonce and lifetime.
// An unfamiliar signing key permits one refresh; invalid signatures do not cause retry storms.
func (c *Client) verifyIdentityToken(ctx context.Context, metadata *identityMetadata, idToken, nonce string) (*identity.Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrUnauthenticated
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var algorithm struct {
		KeyID     string `json:"kid"`
		Algorithm string `json:"alg"`
	}
	if err := json.Unmarshal(header, &algorithm); err != nil || algorithm.Algorithm != model.IdentitySigningAlgorithm {
		return nil, ErrUnauthenticated
	}
	if _, exists := metadata.Keys[algorithm.KeyID]; !exists {
		c.identityCache.Invalidate(c.Snapshot().WebsiteOrigin)
		metadata, err = c.identityCache.Get(ctx, c.Snapshot().WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
		if err != nil {
			return nil, err
		}
	}
	claims, err := identity.VerifyIdentity(
		idToken,
		c.serviceOrigin,
		c.instanceID,
		nonce,
		metadata.Keys,
		time.Now(),
	)
	if err != nil || claims.Email == "" {
		return nil, ErrUnauthenticated
	}
	return claims, nil
}

// identityJSON exchanges bounded protocol documents without retaining provider bodies or token secrets in errors.
func (c *Client) identityJSON(ctx context.Context, method, endpoint string, content io.Reader, document any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, content)
	if err != nil {
		return errors.New("invalid identity request")
	}
	if method == http.MethodPost {
		req.Header.Set(model.HeaderContentType, model.FormMediaType)
	}
	res, err := c.client.Do(req)
	if err != nil {
		return errors.New("identity request failed")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil {
		return errors.New("identity response read failed")
	}
	if res.StatusCode != http.StatusOK || len(encoded) > model.MaximumJSONSize {
		return errors.New("identity request rejected")
	}
	if err := json.Unmarshal(encoded, document); err != nil {
		return errors.New("invalid identity response")
	}
	return nil
}

// VerifyAccessToken checks an instance-bound connector token using the cached Apps signing keys.
func (c *Client) VerifyAccessToken(ctx context.Context, token string) (*identity.AccessClaims, error) {
	if len(token) > 16_384 || !c.authentication {
		return nil, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	metadata, err := c.identityCache.Get(ctx, c.Snapshot().WebsiteOrigin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
	if err != nil {
		return nil, err
	}
	claims, err := identity.VerifyAccess(token, c.serviceOrigin, c.instanceID, metadata.Keys, time.Now(), model.InstanceAccessLifetime)
	if errors.Is(err, identity.ErrUnknownSigningKey) && c.accessKeyRefresh.Allow() {
		origin := c.Snapshot().WebsiteOrigin
		c.identityCache.Invalidate(origin)
		metadata, err = c.identityCache.Get(ctx, origin, otter.LoaderFunc[string, *identityMetadata](c.loadIdentityMetadata))
		if err != nil {
			return nil, err
		}
		claims, err = identity.VerifyAccess(token, c.serviceOrigin, c.instanceID, metadata.Keys, time.Now(), model.InstanceAccessLifetime)
	}
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return claims, nil
}
