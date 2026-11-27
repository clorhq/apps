package model

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Browser authentication lifetimes are shared by hosted Apps and its application SDK.
const (
	DefaultBrowserSessionLifetime = 30 * 24 * time.Hour
	BrowserAuthorizationLifetime  = 24 * time.Hour
)

const (
	ProviderGoogle                  = "google"
	ProviderGitHub                  = "github"
	OAuthAuthorizationCode          = "authorization_code"
	OAuthAccessDenied               = "access_denied"
	RouteIdentityConsent            = "/identity/consent"
	MaximumOAuthStateBytes          = 512
	AuthenticationSignIn            = "signin_succeeded"
	AuthenticationLink              = "link_completed"
	AuthenticationLinkFailure       = "link_failed"
	AuthenticationConsentApproved   = "consent_approved"
	AuthenticationConsentDenied     = "consent_denied"
	AuthenticationExchangeSucceeded = "exchange_succeeded"
	AuthenticationExchangeFailed    = "exchange_failed"
	AuthenticationReasonNone        = "none"
	AuthenticationReasonProof       = "proof_invalid"
	AuthenticationReasonCollision   = "account_collision"
	AuthenticationReasonExpired     = "expired"
	AuthenticationReasonSession     = "session_changed"
	AuthenticationReasonCallback    = "callback_invalid"
	AuthenticationReasonVerifier    = "verifier_invalid"
	ApplicationConfigurationRoute   = "/application/configuration"
	DefaultAuthCallbackPath         = "/auth/callback"
	DefaultAuthSignInPath           = "/signin"
	CreateAccountParameter          = "create_account"
	EnvironmentServiceOrigin        = "APPS_SERVICE_ORIGIN"
	EnvironmentWebsiteOrigin        = "APPS_WEBSITE_ORIGIN"
	EnvironmentTeamSlug             = "APPS_TEAM_SLUG"
	EnvironmentAuthSignInPath       = "APPS_AUTH_SIGNIN_PATH"
	EnvironmentInstanceAPIKey       = "APPS_INSTANCE_API_KEY"
	EnvironmentAuthCallbackPath     = "APPS_AUTH_CALLBACK_PATH"
	EnvironmentCookieKey            = "APPS_COOKIE_KEY"
	EnvironmentAuthProviders        = "APPS_AUTH_PROVIDERS"
	EnvironmentVerificationKeySets  = "APPS_VERIFICATION_KEY_SETS"
	IdentityTokenLifetime           = 5 * time.Minute
)

// Command line sign-in uses the OAuth device authorization and token exchange grants.
const (
	RouteIdentityDevice         = "/oauth/device"
	RouteDeviceApproval         = "/approve/:token"
	DeviceApprovalPrefix        = "/approve/"
	OAuthDeviceCodeGrant        = "urn:ietf:params:oauth:grant-type:device_code"
	OAuthTokenExchangeGrant     = "urn:ietf:params:oauth:grant-type:token-exchange"
	OAuthAccessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	OAuthAuthorizationPending   = "authorization_pending"
	OAuthExpiredToken           = "expired_token"
	OAuthInvalidGrant           = "invalid_grant"
	OAuthInvalidRequest         = "invalid_request"
	DeviceAuthorizationLifetime = 5 * time.Minute
	DeviceAuthorizationInterval = 2 * time.Second
	MaximumIdentityNonceBytes   = 512
)

// ApplicationConfiguration contains only application capabilities, never launcher controls or API keys.
type ApplicationConfiguration struct {
	Version         int      `json:"version"`
	AppID           string   `json:"app_id"`
	InstanceID      string   `json:"instance_id"`
	TeamSlug        string   `json:"team_slug"`
	ServiceOrigin   string   `json:"service_origin"`
	WebsiteOrigin   string   `json:"website_origin"`
	AuthSignInPath  string   `json:"auth_signin_path"`
	PrimaryHostname string   `json:"primary_hostname"`
	Aliases         []string `json:"aliases"`
	// CustomDomains are customer-owned names the application serves with its own
	// certificates, which the SDK obtains through ACME.
	CustomDomains       []string          `json:"custom_domains"`
	AuthCallbackPath    string            `json:"auth_callback_path"`
	AuthProviders       []string          `json:"auth_providers"`
	CookieKey           string            `json:"cookie_key"`
	License             *SignedDocument   `json:"license"`
	VerificationKeys    map[string]string `json:"verification_keys"`
	VerificationKeySets []SignedDocument  `json:"verification_key_sets"`
	TLS                 *TLSBundle        `json:"tls"`
	Values              map[string]string `json:"values"`
}

// ValidReturnPath accepts local browser destinations without encoded or scheme-relative ambiguity.
func ValidReturnPath(returnPath string) bool {
	address, err := url.Parse(returnPath)
	return err == nil && strings.HasPrefix(returnPath, "/") &&
		!strings.HasPrefix(returnPath, "//") && address.Host == "" && !address.IsAbs() &&
		!strings.ContainsAny(returnPath, "\\\r\n") &&
		!strings.HasPrefix(address.Path, "//") && !strings.ContainsAny(address.Path, "\\\r\n")
}

var callbackPathPattern = regexp.MustCompile(`^/[A-Za-z0-9/_~.\-]*$`)

// ValidateAuthCallbackPath accepts a canonical absolute path with no URL or encoding ambiguity.
func ValidateAuthCallbackPath(callbackPath string) error {
	if !callbackPathPattern.MatchString(callbackPath) || strings.HasPrefix(callbackPath, "//") ||
		path.Clean(callbackPath) != callbackPath {
		return errors.New("authentication callback must be a normalized absolute path")
	}
	return nil
}

// ValidateAuthPaths requires separate canonical local routes for initiation and callback.
func ValidateAuthPaths(signInPath, callbackPath string) error {
	if err := ValidateAuthCallbackPath(callbackPath); err != nil {
		return err
	}
	if err := ValidateAuthCallbackPath(signInPath); err != nil {
		return errors.New("authentication Sign In must be a normalized absolute path")
	}
	if signInPath == callbackPath {
		return errors.New("authentication Sign In and callback paths must differ")
	}
	return nil
}
