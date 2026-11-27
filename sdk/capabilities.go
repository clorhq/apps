package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/clorhq/apps/license"
	"github.com/clorhq/apps/model"

	"golang.org/x/crypto/acme"
)

// License returns verified license claims and a separate expiry indicator for application policy.
func (c *Client) License() (*model.License, bool, error) {
	c.mutex.RLock()
	configuration := cloneConfiguration(c.configuration)
	keys := maps.Clone(c.licenseKeys)
	c.mutex.RUnlock()
	if len(keys) == 0 {
		return nil, false, ErrLicenseVerificationUnavailable
	}
	if configuration.License == nil {
		return nil, false, ErrIncompleteConfiguration
	}
	claims, err := license.VerifyLicense(configuration.License, keys, c.appID, c.instanceID, time.Now())
	if err != nil {
		return nil, false, err
	}
	return claims, license.Expired(claims, time.Now()), nil
}

// Feature returns a feature value and preserves expiry separately from application policy.
func (c *Client) Feature(name string) (bool, bool, error) {
	claims, expired, err := c.License()
	if err != nil {
		return false, false, err
	}
	return claims.Features[name], expired, nil
}

// Limit distinguishes absent limits from zero and preserves the unlimited value of minus one.
func (c *Client) Limit(name string) (int64, bool, bool, error) {
	claims, expired, err := c.License()
	if err != nil {
		return 0, false, false, err
	}
	limit, exists := claims.Limits[name]
	return limit, exists, expired, nil
}

// TLSConfig supplies current certificates at each handshake while the application owns the
// server. Apps names use the Apps certificate; custom domains use ACME certificates when a
// certificate cache directory is configured. acme-tls/1 lets TLS-ALPN-01 work on port 443.
// Every name serves the application; none redirects.
func (c *Client) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: c.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

// HTTPChallengeHandler answers ACME HTTP-01 challenges for custom domains on port 80 and
// passes every other request to fallback.
func (c *Client) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	if c.customCertificates == nil {
		return fallback
	}
	return c.customCertificates.HTTPHandler(fallback)
}

// customDomainPolicy allows ACME issuance only for the current configuration's custom domains.
func (c *Client) customDomainPolicy(_ context.Context, host string) error {
	if !c.customDomain(host) {
		return errors.New("TLS hostname is not a custom domain of this instance")
	}
	return nil
}

// customDomain reports whether a name is one of the instance's current custom domains.
func (c *Client) customDomain(host string) bool {
	c.mutex.RLock()
	configuration := c.configuration
	c.mutex.RUnlock()
	return configuration != nil && host != "" && slices.Contains(configuration.CustomDomains, host)
}

// GetCertificate rejects expired certificates and unauthorized SNI without fetching configuration.
// The live custom domain list is checked on every handshake, so a cached certificate for a
// removed name is refused.
func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && c.customDomain(hello.ServerName) {
		if c.customCertificates == nil {
			return nil, errors.New("custom domains need a certificate cache directory")
		}
		return c.customCertificates.GetCertificate(hello)
	}
	c.mutex.RLock()
	configuration := c.configuration
	pair := c.certificate
	c.mutex.RUnlock()
	if pair == nil {
		return nil, ErrIncompleteConfiguration
	}
	if hello == nil || hello.ServerName == "" ||
		hello.ServerName != configuration.PrimaryHostname && !slices.Contains(configuration.Aliases, hello.ServerName) {
		return nil, errors.New("TLS hostname is not authorized")
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return nil, errors.New("TLS certificate is outside its validity period")
	}
	if err := pair.Leaf.VerifyHostname(hello.ServerName); err != nil {
		return nil, errors.New("TLS hostname is not covered")
	}
	return pair, nil
}

// configurationCertificate parses TLS once when preparing a validated internal snapshot.
func configurationCertificate(configuration *Configuration) (*tls.Certificate, error) {
	if configuration.TLS == nil {
		return nil, nil
	}
	pair, err := tls.X509KeyPair([]byte(configuration.TLS.Certificate), []byte(configuration.TLS.PrivateKey))
	if err != nil {
		return nil, errors.New("invalid TLS certificate")
	}
	return &pair, nil
}
