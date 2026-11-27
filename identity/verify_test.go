package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/clorhq/apps/model"
	"github.com/stretchr/testify/require"
)

// TestIdentityValidation rejects incorrect token authority, nonce, signatures and validity periods.
func TestIdentityValidation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	original := Claims{
		Issuer:        "https://api.example.com",
		Audience:      "example-instance",
		Subject:       "opaque-user",
		Email:         "alex@example.com",
		EmailVerified: true,
		Nonce:         "browser-nonce",
		Issued:        now.Unix(),
		Expires:       now.Add(model.IdentityTokenLifetime).Unix(),
	}
	for _, scenario := range []string{
		"valid", "issuer", "audience", "nonce", "expired", "future",
		"lifetime", "unverified", "subject", "algorithm", "signature", "unknown-key",
	} {
		t.Run(scenario, func(t *testing.T) {
			claims := original
			algorithm := model.IdentitySigningAlgorithm
			keyID := "example-key"
			switch scenario {
			case "issuer":
				claims.Issuer = "https://other.example"
			case "audience":
				claims.Audience = "other-instance"
			case "nonce":
				claims.Nonce = "other-nonce"
			case "expired":
				claims.Expires = now.Unix()
			case "future":
				claims.Issued = now.Add(2 * time.Minute).Unix()
			case "lifetime":
				claims.Expires = now.Add(time.Hour).Unix()
			case "unverified":
				claims.EmailVerified = false
			case "subject":
				claims.Subject = ""
			case "algorithm":
				algorithm = "none"
			case "unknown-key":
				keyID = "other-key"
			}
			header, err := json.Marshal(map[string]string{"alg": algorithm, "kid": keyID})
			require.NoError(t, err)
			encoded, err := json.Marshal(claims)
			require.NoError(t, err)
			unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(encoded)
			signature := ed25519.Sign(privateKey, []byte(unsigned))
			if scenario == "signature" {
				signature[0] ^= 1
			}
			token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
			_, err = VerifyIdentity(
				token,
				original.Issuer,
				original.Audience,
				original.Nonce,
				map[string]ed25519.PublicKey{"example-key": publicKey},
				now,
			)
			if scenario == "valid" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
