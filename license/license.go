// Package license signs and verifies versioned instance licenses.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clorhq/apps/model"
)

// ErrLicense matches every license verification failure.
var ErrLicense = errors.New("license is invalid")

// Specific verification failures. Each also matches ErrLicense.
var (
	ErrLicenseFormat    = fmt.Errorf("%w: the license is malformed", ErrLicense)
	ErrLicenseVersion   = fmt.Errorf("%w: this license needs a newer version", ErrLicense)
	ErrLicenseKey       = fmt.Errorf("%w: the license was signed by an unknown key", ErrLicense)
	ErrLicenseAudience  = fmt.Errorf("%w: the license belongs to another app or instance", ErrLicense)
	ErrLicenseSignature = fmt.Errorf("%w: the license signature does not match", ErrLicense)
)

// Sign signs a versioned document with a key identifier bound into the signature.
func Sign(keyID string, signingKey ed25519.PrivateKey, document any) (model.SignedDocument, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return model.SignedDocument{}, ErrLicenseKey
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return model.SignedDocument{}, err
	}
	// Include the key identifier and protocol context in the signature.
	signature := ed25519.Sign(signingKey, append([]byte(signatureContext+keyID+signatureSeparator), documentJSON...))
	return model.SignedDocument{
		KeyID:     keyID,
		Document:  base64.RawURLEncoding.EncodeToString(documentJSON),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// Verify authenticates a signed document using its published verification key.
func Verify(document *model.SignedDocument, verificationKeys map[string]ed25519.PublicKey) ([]byte, error) {
	verificationKey := verificationKeys[document.KeyID]
	if len(verificationKey) != ed25519.PublicKeySize {
		return nil, ErrLicenseKey
	}
	documentJSON, err := base64.RawURLEncoding.DecodeString(document.Document)
	if err != nil {
		return nil, ErrLicenseFormat
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil {
		return nil, ErrLicenseFormat
	}
	if !ed25519.Verify(
		verificationKey,
		append([]byte(signatureContext+document.KeyID+signatureSeparator), documentJSON...),
		signature,
	) {
		return nil, ErrLicenseSignature
	}
	return documentJSON, nil
}

// VerifyLicense authenticates claims, version and audience. It checks the term's
// shape but not whether it has started or ended; use Started and Expired for that.
func VerifyLicense(
	document *model.SignedDocument,
	verificationKeys map[string]ed25519.PublicKey,
	appID, instanceID string,
	now time.Time,
) (*model.License, error) {
	licenseJSON, err := Verify(document, verificationKeys)
	if err != nil {
		return nil, err
	}
	// Read the version before the full decode so a newer document is never misread.
	var versioned struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(licenseJSON, &versioned); err != nil {
		return nil, ErrLicenseFormat
	}
	if versioned.Version > model.ProtocolVersion {
		return nil, ErrLicenseVersion
	}
	if versioned.Version != model.ProtocolVersion {
		return nil, ErrLicenseFormat
	}
	var claims model.License
	if err := json.Unmarshal(licenseJSON, &claims); err != nil {
		return nil, ErrLicenseFormat
	}
	if claims.AppID != appID || claims.InstanceID != instanceID {
		return nil, ErrLicenseAudience
	}
	if !claims.Starts.Before(claims.Expires) || claims.Issued.After(now.Add(ClockTolerance)) {
		return nil, ErrLicenseFormat
	}
	return &claims, nil
}

// Started reports whether the license term has begun.
func Started(claims *model.License, now time.Time) bool {
	return !now.Before(claims.Starts)
}

// Expired reports whether the license term has ended.
func Expired(claims *model.License, now time.Time) bool {
	return !now.Before(claims.Expires)
}
