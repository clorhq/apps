package model

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	ConfigurationRoute        = "/configuration"
	PingRoute                 = "/ping"
	EnvironmentTLSKey         = "TLS_PRIVATE_KEY"
	EnvironmentTLSCertificate = "TLS_CERTIFICATE"
	EnvironmentDomainPrimary  = "DOMAIN_PRIMARY"
	EnvironmentDomainAliases  = "DOMAIN_ALIASES"
	// EnvironmentDomainCustom lists the instance's customer-owned domains, comma separated.
	EnvironmentDomainCustom = "DOMAIN_CUSTOM"
	EnvironmentLicense      = "LICENSE"
)

type Hostname struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	CertificateName string `json:"certificate_name"`
	Status          string `json:"status"`
}
type TLSBundle struct {
	PrivateKey  string    `json:"private_key"`
	Certificate string    `json:"certificate"`
	Expires     time.Time `json:"expires"`
}
type Snapshot struct {
	InstanceID            string                    `json:"instance_id"`
	HostnameID            string                    `json:"hostname_id"`
	DestinationHostnameID string                    `json:"destination_hostname_id"`
	Configuration         InstanceConfiguration     `json:"configuration"`
	License               *SignedDocument           `json:"license"`
	Release               *SignedDocument           `json:"release"`
	Hostnames             []Hostname                `json:"hostnames"`
	VerificationKeys      []SignedDocument          `json:"verification_keys"`
	TLS                   *TLSBundle                `json:"tls"`
	Application           *ApplicationConfiguration `json:"application"`
}
type InstanceReport struct {
	Addresses           []string `json:"addresses"`
	LauncherVersion     string   `json:"launcher_version"`
	ApplicationVersion  string   `json:"application_version"`
	UptimeMillis        int64    `json:"uptime_millis"`
	Healthy             bool     `json:"healthy"`
	Received            string   `json:"received"`
	Applied             string   `json:"applied"`
	Failure             string   `json:"failure"`
	LicenseExpired      bool     `json:"license_expired"`
	CPUCount            int      `json:"cpu_count"`
	LoadAverage         string   `json:"load_average"`
	MemoryTotal         int64    `json:"memory_total"`
	MemoryAvailable     int64    `json:"memory_available"`
	FilesystemTotal     int64    `json:"filesystem_total"`
	FilesystemAvailable int64    `json:"filesystem_available"`
}

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateEnvironment rejects malformed declarations and names owned by the launcher.
func ValidateEnvironment(values map[string]string) error {
	for name, value := range values {
		if !environmentNamePattern.MatchString(name) || strings.ContainsRune(value, 0) {
			return errors.New("invalid application environment variable")
		}
		switch name {
		case EnvironmentTLSKey, EnvironmentTLSCertificate, EnvironmentDomainPrimary, EnvironmentDomainAliases,
			EnvironmentDomainCustom, EnvironmentLicense:
			return errors.New("application settings collide with a managed environment variable")
		}
		if strings.HasPrefix(name, "APPS_") {
			return errors.New("application settings collide with a managed environment variable")
		}
	}
	return nil
}
