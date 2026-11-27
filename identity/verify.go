package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/clorhq/apps/model"
)

var ErrUnknownSigningKey = errors.New("unrecognized token signing key")

type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	Issued        int64  `json:"iat"`
	Expires       int64  `json:"exp"`
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	// Owner reports whether the identity was an admin of the instance’s team when the token was issued.
	Owner bool `json:"owner"`
}

// VerifyIdentity validates identity only. The caller decides local application
// membership and permissions independently of billing customer ownership.
func VerifyIdentity(
	token, issuer, clientID, nonce string,
	verificationKeys map[string]ed25519.PublicKey,
	now time.Time,
) (*Claims, error) {
	invalid := errors.New("identity token validation failed")
	if nonce == "" {
		return nil, invalid
	}
	claimsJSON, err := verifiedClaims(token, "", verificationKeys)
	if err != nil {
		return nil, err
	}
	var identity Claims
	if err := json.Unmarshal(claimsJSON, &identity); err != nil {
		return nil, invalid
	}
	if identity.Issuer != issuer ||
		identity.Audience != clientID ||
		identity.Subject == "" ||
		identity.Nonce != nonce ||
		identity.Issued <= 0 ||
		identity.Expires-identity.Issued > int64(model.IdentityTokenLifetime/time.Second) ||
		identity.Expires <= now.Unix() ||
		identity.Issued > now.Add(time.Minute).Unix() || identity.Expires <= identity.Issued || !identity.EmailVerified {
		return nil, invalid
	}
	return &identity, nil
}

// verifiedClaims authenticates the header and payload with a trusted app signing key.
func verifiedClaims(token, tokenType string, verificationKeys map[string]ed25519.PublicKey) ([]byte, error) {
	invalid := errors.New("token validation failed")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, invalid
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, invalid
	}

	if (tokenType != "" && header.Type != tokenType) ||
		(tokenType == "" && header.Type == model.AccessTokenType) ||
		header.Algorithm != model.IdentitySigningAlgorithm || header.KeyID == "" {
		return nil, invalid
	}
	verificationKey, exists := verificationKeys[header.KeyID]
	if !exists {
		return nil, ErrUnknownSigningKey
	}
	if len(verificationKey) != ed25519.PublicKeySize {
		return nil, invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(verificationKey, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, invalid
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, invalid
	}
	return claimsJSON, nil
}

// AccessClaims describes a delegated grant bound to exactly one resource.
type AccessClaims struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	Audience     string `json:"aud"`
	ClientID     string `json:"client_id"`
	ConnectionID string `json:"connection_id"`
	DemoTeamID   string `json:"demo_team_id,omitempty"`
	TokenID      string `json:"jti"`
	Scope        string `json:"scope"`
	Email        string `json:"email"`
	Owner        bool   `json:"owner"`
	Issued       int64  `json:"iat"`
	Expires      int64  `json:"exp"`
}

// VerifyAccess validates an explicitly typed access token for a single trusted audience.
func VerifyAccess(token, issuer, audience string, keys map[string]ed25519.PublicKey, now time.Time, lifetime time.Duration) (*AccessClaims, error) {
	claimsJSON, err := verifiedClaims(token, model.AccessTokenType, keys)
	if err != nil {
		return nil, err
	}
	var claims AccessClaims
	if json.Unmarshal(claimsJSON, &claims) != nil ||
		claims.Audience != audience ||
		claims.Issuer != issuer ||
		claims.Subject == "" ||
		claims.Email == "" ||
		claims.ClientID == "" ||
		claims.TokenID == "" ||
		claims.ConnectionID == "" ||
		claims.Scope == "" ||
		claims.Issued <= 0 ||
		claims.Issued > now.Add(time.Minute).Unix() ||
		claims.Expires <= now.Unix() ||
		claims.Expires <= claims.Issued ||
		claims.Expires-claims.Issued > int64(lifetime/time.Second) {
		return nil, errors.New("access token validation failed")
	}
	return &claims, nil
}
