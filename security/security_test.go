package security

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSealingBindsResourceAndMasterKey verifies sealing binds resource and master key.
func TestSealingBindsResourceAndMasterKey(t *testing.T) {
	master := bytes.Repeat([]byte{1}, EncryptionKeySize)
	encrypted, err := Seal(master, "example-app/example-credential", []byte("example-secret"))
	require.NoError(t, err)
	secret, err := Open(master, "example-app/example-credential", encrypted)
	require.NoError(t, err)
	require.Equal(t, "example-secret", string(secret))
	_, err = Open(master, "other-app/example-credential", encrypted)
	require.ErrorIs(t, err, ErrCredential)
	_, err = Open(bytes.Repeat([]byte{2}, EncryptionKeySize), "example-app/example-credential", encrypted)
	require.ErrorIs(t, err, ErrCredential)
	require.GreaterOrEqual(t, len(Token()), 43)
}
