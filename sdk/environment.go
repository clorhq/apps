package sdk

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"

	"github.com/clorhq/apps/model"
)

// LoadEnvironment decodes the managed bootstrap contract without modifying process environment.
func LoadEnvironment() (*Configuration, string, error) {
	configuration := &Configuration{
		Version:          model.ProtocolVersion,
		AppID:            strings.TrimSpace(os.Getenv(model.EnvironmentAppID)),
		InstanceID:       strings.TrimSpace(os.Getenv(model.EnvironmentInstanceID)),
		TeamSlug:         strings.TrimSpace(os.Getenv(model.EnvironmentTeamSlug)),
		ServiceOrigin:    strings.TrimSpace(os.Getenv(model.EnvironmentServiceOrigin)),
		WebsiteOrigin:    strings.TrimSpace(os.Getenv(model.EnvironmentWebsiteOrigin)),
		AuthSignInPath:   strings.TrimSpace(os.Getenv(model.EnvironmentAuthSignInPath)),
		PrimaryHostname:  strings.TrimSpace(os.Getenv(model.EnvironmentDomainPrimary)),
		AuthCallbackPath: strings.TrimSpace(os.Getenv(model.EnvironmentAuthCallbackPath)),
		CookieKey:        strings.TrimSpace(os.Getenv(model.EnvironmentCookieKey)),
	}
	if configuration.AuthCallbackPath == "" {
		configuration.AuthCallbackPath = model.DefaultAuthCallbackPath
	}
	if configuration.AuthSignInPath == "" {
		configuration.AuthSignInPath = model.DefaultAuthSignInPath
	}
	for _, mapping := range []struct {
		name   string
		target *[]string
	}{
		{model.EnvironmentDomainAliases, &configuration.Aliases},
		{model.EnvironmentDomainCustom, &configuration.CustomDomains},
		{model.EnvironmentAuthProviders, &configuration.AuthProviders},
	} {
		if value := strings.TrimSpace(os.Getenv(mapping.name)); value != "" {
			for _, item := range strings.Split(value, ",") {
				*mapping.target = append(*mapping.target, strings.TrimSpace(item))
			}
		}
	}
	for _, mapping := range []struct {
		name   string
		target any
	}{
		{model.EnvironmentLicense, &configuration.License},
		{model.EnvironmentVerificationKeys, &configuration.VerificationKeys},
		{model.EnvironmentVerificationKeySets, &configuration.VerificationKeySets},
	} {
		if value := strings.TrimSpace(os.Getenv(mapping.name)); value != "" {
			document, err := base64.StdEncoding.DecodeString(value)
			if err != nil || json.Unmarshal(document, mapping.target) != nil || string(document) == "null" {
				return nil, "", errors.New("invalid managed " + mapping.name + " value")
			}
		}
	}
	certificate, privateKey := strings.TrimSpace(os.Getenv(model.EnvironmentTLSCertificate)), strings.TrimSpace(os.Getenv(model.EnvironmentTLSKey))
	if certificate != "" || privateKey != "" {
		certificatePEM, certificateErr := base64.StdEncoding.DecodeString(certificate)
		keyPEM, keyErr := base64.StdEncoding.DecodeString(privateKey)
		if certificateErr != nil || keyErr != nil || len(keyPEM) == 0 {
			return nil, "", errors.New("invalid managed TLS values")
		}
		block, _ := pem.Decode(certificatePEM)
		if block == nil {
			return nil, "", errors.New("invalid managed TLS certificate")
		}
		parsedCertificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", errors.New("invalid managed TLS certificate")
		}
		configuration.TLS = &model.TLSBundle{
			Certificate: string(certificatePEM),
			PrivateKey:  string(keyPEM),
			Expires:     parsedCertificate.NotAfter,
		}
	}
	return configuration, strings.TrimSpace(os.Getenv(model.EnvironmentInstanceAPIKey)), nil
}
