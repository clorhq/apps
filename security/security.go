// Package security implements credential sealing and opaque authentication tokens.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

var ErrCredential = errors.New("credential authentication failed")

// Token generates an opaque random token for authentication.
func Token() string { return rand.Text() + rand.Text() }

// Hash hashes a token for storage without retaining its plaintext.
func Hash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// Seal encrypts a secret with a resource-bound authenticated encryption key.
func Seal(master []byte, identity string, secret []byte) (string, error) {
	gcm, err := encryptionCipher(master, identity)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, secret, []byte(identity))), nil
}

// Open authenticates and decrypts a secret in its resource context.
func Open(master []byte, identity, encrypted string) ([]byte, error) {
	gcm, err := encryptionCipher(master, identity)
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil || len(encryptedSecret) < gcm.NonceSize() {
		return nil, ErrCredential
	}
	secret, err := gcm.Open(nil, encryptedSecret[:gcm.NonceSize()], encryptedSecret[gcm.NonceSize():], []byte(identity))
	if err != nil {
		return nil, ErrCredential
	}
	return secret, nil
}

// encryptionCipher derives the resource encryption key and constructs AES-GCM.
func encryptionCipher(master []byte, identity string) (cipher.AEAD, error) {
	if len(master) != EncryptionKeySize {
		return nil, errors.New("encryption key must contain 32 bytes")
	}
	encryptionKey := make([]byte, EncryptionKeySize)
	if _, err := io.ReadFull(
		hkdf.New(
			sha256.New,
			master,
			[]byte(identity),
			[]byte(credentialEncryptionContext),
		),
		encryptionKey,
	); err != nil {
		return nil, err
	}
	aesCipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(aesCipher)
}
