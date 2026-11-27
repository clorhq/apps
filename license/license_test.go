package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/clorhq/apps/model"
)

// testClaims returns a year-long license used by the verification tests.
func testClaims(now time.Time) model.License {
	return model.License{
		Version:      model.ProtocolVersion,
		AppID:        "example-app",
		InstanceID:   "example-instance",
		PlanID:       "example-plan",
		PlanName:     "Startup",
		PlanInterval: model.PlanIntervalYear,
		Revision:     3,
		Issued:       now,
		Starts:       now,
		Expires:      now.AddDate(1, 0, 0),
		Renews:       true,
	}
}

// TestVerifyLicenseTermAndAudience verifies long terms, audience, temporal state and key rotation.
func TestVerifyLicenseTermAndAudience(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Date(2_026, 1, 1, 0, 0, 0, 0, time.UTC)
	claims := testClaims(now)
	document, err := Sign("first", key, claims)
	require.NoError(t, err)
	keys := map[string]ed25519.PublicKey{"first": public}
	verified, err := VerifyLicense(&document, keys, claims.AppID, claims.InstanceID, now)
	require.NoError(t, err)
	require.Equal(t, claims.Expires, verified.Expires)
	require.True(t, Started(verified, now))
	require.False(t, Expired(verified, now.AddDate(0, 11, 0)))
	require.True(t, Expired(verified, claims.Expires))
	require.False(t, Started(verified, now.Add(-time.Second)))

	_, err = VerifyLicense(&document, keys, "another-app", claims.InstanceID, now)
	require.ErrorIs(t, err, ErrLicenseAudience)
	_, err = VerifyLicense(&document, keys, claims.AppID, "another-instance", now)
	require.ErrorIs(t, err, ErrLicenseAudience)
	require.ErrorIs(t, err, ErrLicense)
	_, err = VerifyLicense(&document, keys, claims.AppID, claims.InstanceID, now.Add(-6*time.Minute))
	require.ErrorIs(t, err, ErrLicenseFormat)

	_, err = VerifyLicense(&document, map[string]ed25519.PublicKey{}, claims.AppID, claims.InstanceID, now)
	require.ErrorIs(t, err, ErrLicenseKey)

	secondPublic, secondKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys["second"] = secondPublic
	second, err := Sign("second", secondKey, claims)
	require.NoError(t, err)
	_, err = VerifyLicense(&second, keys, claims.AppID, claims.InstanceID, now)
	require.NoError(t, err)
	_, err = VerifyLicense(&document, keys, claims.AppID, claims.InstanceID, now)
	require.NoError(t, err)
	document.KeyID = "second"
	_, err = Verify(&document, keys)
	require.ErrorIs(t, err, ErrLicenseSignature)
}

// TestVerifyLicenseRejectsVersionsAndEmptyTerms verifies the version gate and term shape.
func TestVerifyLicenseRejectsVersionsAndEmptyTerms(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys := map[string]ed25519.PublicKey{"first": public}
	now := time.Date(2_026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := map[string]any{
		"version":     model.ProtocolVersion + 1,
		"app_id":      "example-app",
		"instance_id": "example-instance",
		"expires":     "not a time in this version",
	}
	document, err := Sign("first", key, future)
	require.NoError(t, err)
	_, err = VerifyLicense(&document, keys, "example-app", "example-instance", now)
	require.ErrorIs(t, err, ErrLicenseVersion)

	older := testClaims(now)
	older.Version = 1
	document, err = Sign("first", key, older)
	require.NoError(t, err)
	_, err = VerifyLicense(&document, keys, older.AppID, older.InstanceID, now)
	require.ErrorIs(t, err, ErrLicenseFormat)

	empty := testClaims(now)
	empty.Expires = empty.Starts
	document, err = Sign("first", key, empty)
	require.NoError(t, err)
	_, err = VerifyLicense(&document, keys, empty.AppID, empty.InstanceID, now)
	require.ErrorIs(t, err, ErrLicenseFormat)

	notStarted := testClaims(now)
	notStarted.Starts = now.AddDate(0, 1, 0)
	document, err = Sign("first", key, notStarted)
	require.NoError(t, err)
	verified, err := VerifyLicense(&document, keys, notStarted.AppID, notStarted.InstanceID, now)
	require.NoError(t, err)
	require.False(t, Started(verified, now))
}

// TestLicenseFileRoundTrip verifies armored files survive rewrapping, indentation and header edits.
func TestLicenseFileRoundTrip(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys := map[string]ed25519.PublicKey{"first": public}
	now := time.Date(2_026, 12, 1, 0, 0, 0, 0, time.UTC)
	claims := testClaims(now)
	document, err := Sign("first", key, claims)
	require.NoError(t, err)
	text, err := EncodeLicenseFile(&document, NewLicenseFileHeader("Example", &claims))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(text, LicenseFileBegin+"\nProduct: Example\nPlan: Startup (year)\n"))
	require.Contains(t, text, "Valid: 2026-12-01 to 2027-12-01\n")
	require.Contains(t, text, "Revision: 3\nFormat: 1\n\n")
	for line := range strings.Lines(text) {
		require.LessOrEqual(t, len(strings.TrimRight(line, "\n")), LicenseFileColumns)
	}

	_, body, _ := strings.Cut(text, "\n\n")
	body, _, _ = strings.Cut(body, LicenseFileEnd)
	joined := strings.Join(strings.Fields(body), "")
	rewrapped := ""
	for len(joined) > 30 {
		rewrapped += "    " + joined[:30] + "  \r\n"
		joined = joined[30:]
	}
	rewrapped += joined
	variants := map[string]string{
		"original": text,
		"crlf":     strings.ReplaceAll(text, "\n", "\r\n"),
		"rewrapped": "Pasted below:\n" + LicenseFileBegin + "\r\nPlan: Enterprise (forever)\r\n" +
			"Product: A long product name that a mail client\nwrapped onto a second line\n\n" +
			rewrapped + "\n" + LicenseFileEnd + "\nThanks",
		"no header": LicenseFileBegin + "\n" + strings.Join(strings.Fields(body), "") + "\n" + LicenseFileEnd,
	}
	for name, variant := range variants {
		document, err := DecodeLicenseFile(variant)
		require.NoError(t, err, name)
		verified, err := VerifyLicense(document, keys, claims.AppID, claims.InstanceID, now)
		require.NoError(t, err, name)
		require.Equal(t, "Startup", verified.PlanName, name)
	}

	_, err = DecodeLicenseFile(text + text)
	require.ErrorIs(t, err, ErrLicenseFormat)
	_, err = DecodeLicenseFile(strings.Repeat(" ", MaximumLicenseFileBytes) + text)
	require.ErrorIs(t, err, ErrLicenseFormat)
	_, err = DecodeLicenseFile(strings.Replace(text, LicenseFileEnd, "", 1))
	require.ErrorIs(t, err, ErrLicenseFormat)

	tampered := document
	tamperedClaims := claims
	tamperedClaims.Expires = claims.Expires.AddDate(10, 0, 0)
	tamperedJSON, err := json.Marshal(tamperedClaims)
	require.NoError(t, err)
	tampered.Document = base64.RawURLEncoding.EncodeToString(tamperedJSON)
	tamperedText, err := EncodeLicenseFile(&tampered, NewLicenseFileHeader("Example", &tamperedClaims))
	require.NoError(t, err)
	tamperedDocument, err := DecodeLicenseFile(tamperedText)
	require.NoError(t, err)
	_, err = VerifyLicense(tamperedDocument, keys, claims.AppID, claims.InstanceID, now)
	require.ErrorIs(t, err, ErrLicenseSignature)
}
