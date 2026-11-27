package sdk

import (
	"time"

	"github.com/clorhq/apps/license"
	"github.com/clorhq/apps/model"
)

// VerifyLicenseFile authenticates an armored license file for an application running
// offline. trustedKeys is the key-ID to public-key map built into the application, the
// `keys` map that `key list` returns. It checks the signature, version, app and instance;
// only the signed body is trusted, never the readable header. Check the term separately
// with license.Started and license.Expired, and choose your own warnings and grace.
func VerifyLicenseFile(text string, trustedKeys map[string]string, appID, instanceID string) (*model.License, error) {
	keys, err := license.ParseKeys(trustedKeys)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrLicenseVerificationUnavailable
	}
	document, err := license.DecodeLicenseFile(text)
	if err != nil {
		return nil, err
	}
	return license.VerifyLicense(document, keys, appID, instanceID, time.Now())
}
