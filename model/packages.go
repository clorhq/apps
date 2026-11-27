package model

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/distribution/reference"

	"github.com/clorhq/apps/security"
)

const (
	EventPackageCreated                 = "package.created"
	EventPackageUpdated                 = "package.updated"
	PackageDaemon                       = "daemon"
	PackageCLI                          = "cli"
	InstallScopeUser                    = "user"
	InstallScopeSystem                  = "system"
	PackageDownload                     = "download"
	MaximumVersionCharacters            = 128
	MaximumArtifacts                    = 100
	MaximumDaemonAccountCharacters      = 32
	MaximumPackageNameCharacters        = 200
	MaximumPackageDescriptionCharacters = 2_000
)

var packageVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
var artifactNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var artifactDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var daemonAccountPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// ValidDaemonAccount accepts portable system account names for generated installations.
func ValidDaemonAccount(account string) bool {
	return len(account) <= MaximumDaemonAccountCharacters && daemonAccountPattern.MatchString(account)
}

// ValidInstallationSlug accepts a system account name that can also select an installed app.
func ValidInstallationSlug(slug string) bool {
	if !ValidDaemonAccount(slug) {
		return false
	}
	switch slug {
	case "apps-launcher", "completion", "config", "help", "install", "list", "register", "run", "setup", "show", "uninstall", "update", "version":
		return false
	}
	return true
}

// ValidExecutable accepts a single portable command name, without paths or shell syntax.
func ValidExecutable(executable string) bool {
	return artifactNamePattern.MatchString(executable)
}

// ValidateCLIRelease requires one raw executable for each explicitly supported platform.
func ValidateCLIRelease(release *Release) error {
	if err := ValidateArtifactRelease(release); err != nil {
		return err
	}
	platforms := map[string]bool{}
	for _, artifact := range release.Artifacts {
		if artifact.Type == ArtifactTypeImage {
			return errors.New("CLI packages install executables; publish container images in a download package")
		}
		if (artifact.OS != "linux" && artifact.OS != "darwin") ||
			(artifact.Architecture != ArchitectureAMD64 && artifact.Architecture != ArchitectureARM64) {
			return errors.New("CLI artifacts require linux or darwin and amd64 or arm64")
		}
		platform := artifact.OS + "/" + artifact.Architecture
		if platforms[platform] {
			return errors.New("CLI releases permit one executable per platform")
		}
		platforms[platform] = true
		for _, suffix := range []string{".zip", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".zst", ".dmg", ".pkg"} {
			if strings.HasSuffix(strings.ToLower(artifact.Filename), suffix) {
				return errors.New("CLI artifacts must be raw executables, not archives or packages")
			}
		}
	}
	return nil
}

// Artifact types. A file is downloaded from its URL; an image is a container image
// reference pulled from its registry by digest.
const (
	ArtifactTypeFile  = "file"
	ArtifactTypeImage = "image"
	// MaximumImagePlatforms bounds the platforms an image artifact lists.
	MaximumImagePlatforms = 16
)

// Artifact describes an immutable public file or container image without implying
// executable behavior. Omitted type means file.
type Artifact struct {
	Type         string `json:"type,omitempty"`
	Name         string `json:"name"`
	Filename     string `json:"filename,omitempty"`
	URL          string `json:"url,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Size         int64  `json:"size,omitempty"`
	OS           string `json:"os,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	// Image is "<registry>/<repository>@sha256:<64 hex>"; the digest is required.
	Image string `json:"image,omitempty"`
	// Platforms lists the image's platforms, such as linux/amd64.
	Platforms []string `json:"platforms,omitempty"`
}

// imagePlatformPattern accepts an OCI platform such as linux/amd64 or linux/arm/v7.
var imagePlatformPattern = regexp.MustCompile(`^(linux|windows)/(amd64|arm64|arm|386|ppc64le|s390x|riscv64)(/v[5-8])?$`)

// errImageReference explains the accepted image reference form.
var errImageReference = errors.New("image artifacts need a registry, a repository and a SHA-256 digest, pinned by SHA-256 digest and without a tag")

// validateImageReference parses an image reference with the Docker grammar and requires
// an explicit registry, a valid port, no tag and a SHA-256 digest.
func validateImageReference(image string) error {
	named, err := reference.ParseNamed(image)
	if err != nil || named.String() != image {
		return errImageReference
	}
	if _, tagged := named.(reference.Tagged); tagged {
		return errImageReference
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().Algorithm() != "sha256" || digested.Digest().Validate() != nil {
		return errImageReference
	}
	registry := reference.Domain(named)
	// ParseNamed fills in docker.io for short names; the reference must name its registry.
	if !strings.HasPrefix(image, registry+"/") {
		return errImageReference
	}
	host, port, err := net.SplitHostPort(registry)
	if err != nil {
		// A registry without a port has nothing more to check.
		return nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || host == "" || number < 1 || number > 65_535 {
		return errImageReference
	}
	return nil
}

// validateImageArtifact checks an image reference by digest and its platforms.
func validateImageArtifact(artifact *Artifact) error {
	if artifact.URL != "" || artifact.SHA256 != "" || artifact.Size != 0 || artifact.OS != "" || artifact.Architecture != "" {
		return errors.New("image artifacts have an image and platforms, not a URL, checksum, size, os or architecture")
	}
	if err := validateImageReference(artifact.Image); err != nil {
		return err
	}
	if len(artifact.Platforms) == 0 || len(artifact.Platforms) > MaximumImagePlatforms {
		return errors.New("image artifacts list 1 to " + strconv.Itoa(MaximumImagePlatforms) + " platforms such as linux/amd64")
	}
	platforms := map[string]bool{}
	for _, platform := range artifact.Platforms {
		if !imagePlatformPattern.MatchString(platform) || platforms[platform] {
			return errors.New("image platforms are unique values such as linux/amd64 or linux/arm/v7")
		}
		platforms[platform] = true
	}
	return nil
}

// ValidateArtifactRelease checks version labels and immutable artifact declarations without fetching bytes.
func ValidateArtifactRelease(release *Release) error {
	if release == nil || len(release.Version) > MaximumVersionCharacters || !packageVersionPattern.MatchString(release.Version) ||
		len(release.Artifacts) == 0 || len(release.Artifacts) > MaximumArtifacts || len(release.Variants) != 0 {
		return errors.New("package release requires a URL-safe version and between 1 and 100 artifacts without application variants")
	}
	artifactNames := map[string]bool{}
	for _, artifact := range release.Artifacts {
		if !artifactNamePattern.MatchString(artifact.Name) || artifactNames[artifact.Name] {
			return errors.New("artifact names must be unique lowercase letters, digits and hyphens")
		}
		artifactNames[artifact.Name] = true
		switch artifact.Type {
		case ArtifactTypeImage:
			if err := validateImageArtifact(&artifact); err != nil {
				return err
			}
			continue
		case "", ArtifactTypeFile:
		default:
			return errors.New("artifact type must be file or image")
		}
		if len(artifact.Platforms) != 0 || artifact.Image != "" {
			return errors.New("only image artifacts have an image and platforms")
		}
		if artifact.Filename == "" || len(artifact.Filename) > 255 || artifact.Filename == "." || artifact.Filename == ".." ||
			strings.ContainsAny(artifact.Filename, "/\\\x00\r\n") {
			return errors.New("artifact requires a display filename without path separators")
		}
		if err := security.ValidateFileURL(artifact.URL); err != nil {
			return err
		}
		if !artifactDigestPattern.MatchString(artifact.SHA256) || artifact.Size <= 0 {
			return errors.New("artifact requires a lowercase SHA-256 checksum and positive byte size")
		}
		for _, label := range []string{artifact.OS, artifact.Architecture} {
			if label != "" && !artifactNamePattern.MatchString(label) {
				return errors.New("platform labels use lowercase letters, digits and hyphens")
			}
		}
	}
	return nil
}

const (
	RoutePackages        = "/packages"
	RoutePackageMetadata = "/pkg/metadata"
	RoutePackageVersion  = "/pkg/:package_slug/versions/:version/:artifact"
	RoutePackageChannel  = "/pkg/:package_slug/:channel/:artifact"
)

// Package describes a public package and its available releases.
type Package struct {
	InstallationAvailable bool             `json:"installation_available"`
	Type                  string           `json:"type"`
	InstallScope          string           `json:"install_scope,omitempty"`
	Executable            string           `json:"executable,omitempty"`
	Slug                  string           `json:"slug"`
	Name                  string           `json:"name"`
	Description           string           `json:"description"`
	Releases              []PackageRelease `json:"releases"`
}

// PackageRelease publishes immutable artifact metadata and its signed manifest.
type PackageRelease struct {
	Version   string         `json:"version"`
	Artifacts []Artifact     `json:"artifacts"`
	Channels  []string       `json:"channels"`
	Signature SignedDocument `json:"signature"`
}

// Packages is the public discovery document for developer-hosted files.
type Packages struct {
	Packages []Package `json:"packages"`
	Count    int       `json:"count"`
}
