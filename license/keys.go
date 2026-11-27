package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/clorhq/apps/model"
)

// ParseKeys validates and copies application-supplied Ed25519 trust roots.
func ParseKeys(encodedKeys map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(encodedKeys))
	for id, encoded := range encodedKeys {
		key, err := base64.RawURLEncoding.DecodeString(encoded)
		if id == "" || strings.TrimSpace(id) != id || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid verification key")
		}
		keys[id] = key
	}
	return keys, nil
}

// AdmitKeys stages append-only trust from a key set signed by an existing trusted key.
func AdmitKeys(trusted map[string]ed25519.PublicKey, documents []model.SignedDocument, appID string) (map[string]ed25519.PublicKey, error) {
	keys := maps.Clone(trusted)
	if len(documents) == 0 {
		return keys, nil
	}
	for _, document := range documents {
		if _, exists := trusted[document.KeyID]; !exists {
			continue
		}
		keySetJSON, err := Verify(&document, trusted)
		if err != nil {
			return nil, err
		}
		var keySet model.VerificationKeys
		if err := json.Unmarshal(keySetJSON, &keySet); err != nil {
			return nil, err
		}
		if keySet.Version != model.ProtocolVersion || keySet.AppID != appID || len(keySet.Keys) == 0 {
			return nil, errors.New("verification key set audience mismatch")
		}
		additions, err := ParseKeys(keySet.Keys)
		if err != nil {
			return nil, err
		}
		for id, key := range additions {
			previous, exists := keys[id]
			if exists && !slices.Equal(previous, key) {
				return nil, errors.New("verification key replacement is forbidden")
			}
			keys[id] = key
		}
		return keys, nil
	}
	return nil, errors.New("verification key set has no trusted signature")
}
