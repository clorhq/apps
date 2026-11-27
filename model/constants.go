package model

import (
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	AppAvailabilityAvailable    = "available"
	AppAvailabilityUnavailable  = "unavailable"
	AppAvailabilityInitializing = "initializing"
)

// RouteDeveloperSchema publishes the developer contract for unauthenticated discovery.
const RouteDeveloperSchema = "/v1/openapi.json"

const AppStatusDraft = "draft"
const AppStatusPublished = "published"
const UpdateModeAutomatic = "automatic"
const UpdateModeManual = "manual"
const EventReleasePromoted = "release.promoted"
const EventReleaseWithdrawn = "release.withdrawn"

// Resource states are shared by persistence, API projections and instance agents.
const (
	BillingStatusActive      = "active"
	BillingStatusPending     = "pending"
	BillingStatusScheduled   = "scheduled"
	BillingStatusFailed      = "failed"
	CertificateStatusPending = "pending"
	CertificateStatusReady   = "ready"
	CertificateStatusFailed  = "failed"
	NamespaceStatusPending   = "pending"
	NamespaceStatusReady     = "ready"
	NamespaceStatusFailed    = "failed"
)

// ServiceDomain is the canonical infrastructure target for team DNS aliases.
const ServiceDomain = "apps.clor.com"

// Protocol values shared by developers, installed applications, and service handlers.
const (
	VariantNative                  = "native"
	VariantCompose                 = "compose"
	ChannelStable                  = "stable"
	DefaultTimezone                = "UTC"
	BillingModeTest                = "test"
	BillingModeLive                = "live"
	PlanIntervalMonth              = "month"
	PlanIntervalYear               = "year"
	PlanIntervalFree               = "free"
	PlanIntervalTrial              = "trial"
	MaximumArchiveSize             = 536_870_912
	MaximumJSONSize                = 2_000_000
	MaximumInstanceAddresses       = 8
	DefaultPageSize                = 100
	MaximumPageSize                = 500
	EnvironmentAppID               = "APPS_APP_ID"
	EnvironmentInstanceID          = "APPS_INSTANCE_ID"
	EnvironmentVerificationKeys    = "APPS_VERIFICATION_KEYS"
	HeaderETag                     = "ETag"
	HeaderIfNoneMatch              = "If-None-Match"
	HeaderRetryAfter               = "Retry-After"
	HeaderCacheControl             = "Cache-Control"
	HeaderContentSecurityPolicy    = "Content-Security-Policy"
	HeaderWebhookSignature         = "Apps-Signature"
	HeaderWebhookEventID           = "Apps-Event-ID"
	RouteClaim                     = "/claim"
	RouteClaimNameCheck            = "/claim/name/check"
	RouteGoogleSignIn              = "/auth/google"
	RouteGoogleCallback            = "/auth/callback"
	RouteGitHubSignIn              = "/auth/github"
	RouteGitHubCallback            = "/auth/github/callback"
	RouteSignIn                    = "/signin"
	RouteAccountLink               = "/auth/link"
	RouteHostedLogout              = "/auth/logout"
	RouteIdentityKeys              = "/.well-known/jwks.json"
	RouteIdentityDiscovery         = "/.well-known/openid-configuration"
	RouteIdentityAuthorize         = "/oauth/authorize"
	RouteIdentityToken             = "/oauth/token"
	InstanceAPIPrefix              = "/api/v1/instances/"
	RouteInstanceRegister          = "/api/v1/register"
	IdentitySigningAlgorithm       = "EdDSA"
	IdentityKeyType                = "OKP"
	IdentityKeyCurve               = "Ed25519"
	IdentityPKCEMethod             = "S256"
	HeaderAuthorization            = "Authorization"
	HeaderContentType              = "Content-Type"
	HeaderOrigin                   = "Origin"
	JSONMediaType                  = "application/json"
	FormMediaType                  = "application/x-www-form-urlencoded"
	IdentityTokenType              = "JWT"
	OAuthBearerType                = "Bearer"
	BearerPrefix                   = "Bearer "
	HostnameStatusPending          = "pending"
	HostnameStatusReady            = "ready"
	HostnameStatusProvisioned      = "provisioned"
	EventAppCreated                = "app.created"
	EventAppUpdated                = "app.updated"
	EventCertificateInstalled      = "certificate.installed"
	EventCertificateIssued         = "certificate.issued"
	EventContentCreated            = "content.created"
	EventContentPublished          = "content.published"
	EventCredentialReplaced        = "credential.replaced"
	EventDomainVerified            = "domain.verified"
	EventDomainReleased            = "domain.released"
	EventLicenseChanged            = "license.changed"
	EventHostnameChanged           = "hostname.changed"
	EventHostnameCreated           = "hostname.created"
	EventHostnameMoveRequested     = "hostname.move_requested"
	EventHostnameProvisioned       = "hostname.provisioned"
	EventInstanceClaimed           = "instance.claimed"
	EventInstanceConfigured        = "instance.configured"
	EventInstanceLabeled           = "instance.labeled"
	EventInstanceCredentialRotated = "instance.credential_rotated"
	EventInstanceRegistered        = "instance.registered"
	EventInstanceRevoked           = "instance.revoked"
	EventIntegrationCreated        = "integration.created"
	EventIntegrationRevoked        = "integration.revoked"
	EventIntegrationRotated        = "integration.rotated"
	EventNamespaceCreated          = "namespace.created"
	EventNamespaceDNSChanged       = "namespace.dns_changed"
	EventNamespaceRoutingChanged   = "namespace.routing_changed"
	EventPlanCreated               = "plan.created"
	EventReleaseCatalogUpdated     = "release.catalog.updated"
	EventReleasePublished          = "release.published"
	EventSubscriptionChanged       = "subscription.changed"
	EventUpdateFailed              = "update.failed"
	EventUpdateInstalled           = "update.installed"
	EventWebhookCreated            = "webhook.created"
	EventWebhookUpdated            = "webhook.updated"
)

// Provider setup events and test outcomes are persisted in app-owned resources.
const (
	EventEmailConfigured         = "email.configured"
	EventEmailTest               = "email.test"
	EventZoneCreated             = "zone.created"
	EventZoneVerified            = "zone.verified"
	EventZoneCredentialsReplaced = "zone.credentials_replaced"
	EmailTestStatusAccepted      = "accepted"
	EmailTestStatusFailed        = "failed"
	EmailTestStatusUnknown       = "unknown"
)

// MaximumPlanTaglineCharacters bounds a plan's tagline on pricing cards.
const MaximumPlanTaglineCharacters = 80

// Plan lifecycle values distinguish availability; activation fixes a plan's price terms.
const (
	PlanStatusDraft       = "draft"
	PlanStatusActive      = "active"
	PlanStatusArchived    = "archived"
	PromoDurationOnce     = "once"
	PromoDurationOngoing  = "ongoing"
	EventPlanUpdated      = "plan.updated"
	EventPlanActivated    = "plan.activated"
	EventPlanArchived     = "plan.archived"
	EventPlanAccessEnded  = "plan.access_ended"
	EventPromoCreated     = "promo.created"
	EventPromoDeactivated = "promo.deactivated"
)

// TaxStatusRequiresLocationInputs is the automatic tax status of an invoice or
// subscription whose customer address is missing or incomplete.
const TaxStatusRequiresLocationInputs = "requires_location_inputs"

// EventSubscriptionCancelled records a paid subscription that ended and moved its instance to the free plan.
const EventSubscriptionCancelled = "subscription.cancelled"

// EventSigningKeyCreated records additions to the retained signing key set.
const EventSigningKeyCreated = "signing_key.created"

// EventSigningKeyActivated records a pending signing key becoming the license signer.
const EventSigningKeyActivated = "signing_key.activated"

// Signing key states. A key is created pending, becomes active when activated, and
// is superseded once a newer key is activated. Public keys are kept forever.
const (
	SigningKeyStatusPending    = "pending"
	SigningKeyStatusActive     = "active"
	SigningKeyStatusSuperseded = "superseded"
)

// RouteStaticAssets serves the embedded website stylesheet and scripts. Page slugs never contain "_".
const RouteStaticAssets = "/_apps"

// Launcher hosting layout shared by the build script output, website routes, and installer.
const (
	RouteInstaller           = "/pkg/:package_slug/install.sh"
	RouteLauncher            = "/launcher"
	ArchitectureAMD64        = "amd64"
	ArchitectureARM64        = "arm64"
	LauncherArtifactPrefix   = "apps-launcher-linux-"
	LauncherChecksumSuffix   = ".sha256"
	LauncherManifestPrefix   = "latest-linux-"
	LauncherManifestSuffix   = ".txt"
	DefaultLauncherDirectory = "/usr/local/share/apps/launcher"
)

// Launcher host paths shared by the installer and launcher commands.
const (
	LauncherExecutableName = "apps-launcher"
	LauncherStateDirectory = "/var/lib/" + LauncherExecutableName
	LauncherConfigFilename = "config.json"
)

// LauncherConfigPath locates the private config for a validated app slug.
func LauncherConfigPath(slug string) string {
	return path.Join(LauncherStateDirectory, slug, LauncherConfigFilename)
}

// Website page block types select a shared template component.
const (
	BlockTypeHero         = "hero"
	BlockTypeInstall      = "install"
	BlockTypeFeatures     = "features"
	BlockTypeScreenshot   = "screenshot"
	BlockTypeSteps        = "steps"
	BlockTypeFAQ          = "faq"
	BlockTypeCallToAction = "call_to_action"
	BlockTypeLogos        = "logos"
	BlockTypeUseCases     = "use_cases"
	BlockTypeDiagram      = "diagram"
	BlockTypeStats        = "stats"
	BlockTypeDetails      = "details"
	BlockTypePricing      = "pricing"
	// BlockTypeSales places the sales email capture, which posts to /sales.
	BlockTypeSales = "sales"
)

// Team roles. Admins do everything; billing members see the team read-only and
// handle invoices and cards. Roles are never shared with the application.
const (
	TeamRoleAdmin   = "admin"
	TeamRoleBilling = "billing"
)

// Team pages live under /team/<slug>/, where the slug is the team's subdomain.
// TeamPath fills the :team parameter of these routes.
const (
	TeamParameter = ":team"
	// TeamPathPrefix begins every team page route.
	TeamPathPrefix                 = "/team/"
	RouteTeams                     = "/teams"
	RouteTeamCreate                = "/teams/create"
	RouteTeamSubdomainSuggest      = "/teams/subdomain/suggest"
	RouteTeamSubdomainCheck        = "/teams/subdomain/check"
	RouteKnownInstanceForget       = "/teams/instances/forget"
	RouteInvitationAccept          = "/teams/invitations/accept"
	RouteInvitation                = "/invite/:token"
	InvitationPrefix               = "/invite/"
	RouteTeamInstances             = "/team/:team/instances"
	RouteTeamInstance              = "/team/:team/instances/:id"
	RouteTeamInstanceReady         = "/team/:team/instances/:id/ready"
	RouteTeamInstanceStatus        = "/team/:team/instances/:id/ready/status"
	RouteTeamInstancePayment       = RouteTeamInstance + InstancePaymentSuffix
	RouteTeamInstancePaymentStatus = RouteTeamInstance + InstancePaymentStatusSuffix
	RouteTeamInstanceConfigure     = "/team/:team/instances/configure"
	RouteTeamInstancePlan          = "/team/:team/instances/plan"
	// RouteTeamInstancePlanReview reviews one plan choice before it is applied.
	RouteTeamInstancePlanReview = "/team/:team/instances/:id/plan/:plan"
	RouteTeamInstanceRemove     = "/team/:team/instances/remove"
	RouteTeamInstanceLabels     = "/team/:team/instances/labels"
	// RouteTeamInstanceOffline adds a server that runs with a license file to the team.
	RouteTeamInstanceOffline = "/team/:team/instances/license-file"
	// RouteTeamInstanceMode switches an instance between managed and offline.
	RouteTeamInstanceMode = "/team/:team/instances/mode"
	// RouteTeamInstanceLicense downloads an instance's current license file.
	RouteTeamInstanceLicense = "/team/:team/instances/:id/license"
	// RouteTeamInstanceLicenseRenew starts a new free term and downloads its license file.
	RouteTeamInstanceLicenseRenew = "/team/:team/instances/:id/license/renew"
	// RouteTeamInstanceDomains adds a custom domain; RouteTeamInstanceDomainRemove removes one.
	RouteTeamInstanceDomains      = "/team/:team/instances/domains"
	RouteTeamInstanceDomainRemove = "/team/:team/instances/domains/remove"
	// RouteLicenseFile opens the team page of a server that runs with a license file
	// from its instance ID. RouteOffline is the same link's earlier path and redirects.
	RouteLicenseFile            = "/license-file"
	RouteOffline                = "/offline"
	RouteTeamDetails            = "/team/:team/details"
	RouteTeamSettings           = "/team/:team/settings"
	RouteTeamBilling            = "/team/:team/billing"
	RouteTeamBillingPortal      = "/team/:team/billing/portal"
	RouteTeamCard               = "/team/:team/billing/card"
	RouteTeamCardReturn         = "/team/:team/billing/card/return"
	RouteTeamKeys               = "/team/:team/keys"
	RouteTeamKeyRevoke          = "/team/:team/keys/revoke"
	RouteTeamKeyLabels          = "/team/:team/keys/labels"
	RouteTeamDomains            = "/team/:team/domains"
	RouteTeamMembers            = "/team/:team/members"
	RouteTeamMemberInvite       = "/team/:team/members/invite"
	RouteTeamInvitationResend   = "/team/:team/members/resend"
	RouteTeamInvitationRevoke   = "/team/:team/members/revoke"
	RouteTeamMemberRole         = "/team/:team/members/role"
	RouteTeamMemberRemove       = "/team/:team/members/remove"
	RouteTeamOwnerTransfer      = "/team/:team/members/transfer"
	RouteTeamLeave              = "/team/:team/leave"
	InstanceReadySuffix         = "/ready"
	InstancePaymentSuffix       = "/payment"
	InstancePaymentStatusSuffix = InstancePaymentSuffix + "/status"
	InstanceStatusSuffix        = "/ready/status"
)

// TeamPath fills a team route's :team parameter with the team's slug.
func TeamPath(route, slug string) string {
	return strings.Replace(route, TeamParameter, url.PathEscape(slug), 1)
}

// TeamInstancePath is the Manage page of one of a team's instances.
func TeamInstancePath(slug, instanceID string) string {
	return strings.Replace(TeamPath(RouteTeamInstance, slug), ":id", url.PathEscape(instanceID), 1)
}

// TeamInstanceLicensePath downloads the current license file of one of a team's instances.
func TeamInstanceLicensePath(slug, instanceID string) string {
	return strings.Replace(TeamPath(RouteTeamInstanceLicense, slug), ":id", url.PathEscape(instanceID), 1)
}

// TeamInstanceLicenseRenewPath renews the free term of one of a team's instances.
func TeamInstanceLicenseRenewPath(slug, instanceID string) string {
	return strings.Replace(TeamPath(RouteTeamInstanceLicenseRenew, slug), ":id", url.PathEscape(instanceID), 1)
}

// TeamInstancePlanPath is the review page for choosing a plan for one of a team's instances.
func TeamInstancePlanPath(slug, instanceID, planID string) string {
	path := strings.Replace(TeamPath(RouteTeamInstancePlanReview, slug), ":id", url.PathEscape(instanceID), 1)
	return strings.Replace(path, ":plan", url.PathEscape(planID), 1)
}

// Team lifecycle events.
const (
	EventTeamCreated           = "team.created"
	EventTeamMemberAdded       = "team.member_added"
	EventTeamMemberRoleChanged = "team.member_role_changed"
	EventTeamMemberRemoved     = "team.member_removed"
)

// BlockTypeGallery displays external images in a responsive grid.
const BlockTypeGallery = "gallery"

// Block alignment values control section text and content placement.
const (
	BlockAlignStart  = "start"
	BlockAlignCenter = "center"
)

// Instance modes. Managed instances run the launcher; offline instances never contact
// Apps and use downloaded license files.
const (
	InstanceModeManaged = "managed"
	InstanceModeOffline = "offline"
	// AttachmentValidity bounds the one-time install command that attaches a launcher
	// to an offline instance.
	AttachmentValidity = 24 * time.Hour
	// EventInstanceModeChanged records a switch between managed and offline.
	EventInstanceModeChanged = "instance.mode_changed"
)

// Custom domain DNS states and bounds.
const (
	DomainStatusPending  = "pending"
	DomainStatusPointed  = "pointed"
	DomainStatusMismatch = "mismatch"
	// MaximumInstanceDomains bounds the custom domains of one instance.
	MaximumInstanceDomains = 10
	// EventInstanceDomainAdded and EventInstanceDomainRemoved record custom domain changes.
	EventInstanceDomainAdded   = "instance.domain_added"
	EventInstanceDomainRemoved = "instance.domain_removed"
)

// License term defaults and bounds.
const (
	// DefaultFreeTermDays is the unpaid term of a free plan created without one.
	DefaultFreeTermDays = 365
	// DefaultTrialTermDays is the term of a trial plan created without one.
	DefaultTrialTermDays = 14
	// MaximumTermDays bounds the unpaid term of a free or trial plan.
	MaximumTermDays = 3_650
)

// License issuance reasons recorded with every license revision.
const (
	LicenseReasonPurchase       = "purchase"
	LicenseReasonChange         = "change"
	LicenseReasonRenewal        = "renewal"
	LicenseReasonCancellation   = "cancellation"
	LicenseReasonLapse          = "lapse"
	LicenseReasonTrial          = "trial"
	LicenseReasonTrialExtension = "trial_extension"
	LicenseReasonTermRenewal    = "term_renewal"
	LicenseReasonContract       = "contract"
	LicenseReasonMode           = "mode"
	LicenseReasonTerms          = "terms"
)

// LicenseReasons lists every license issuance reason in schema order.
var LicenseReasons = []string{
	LicenseReasonPurchase,
	LicenseReasonChange,
	LicenseReasonRenewal,
	LicenseReasonCancellation,
	LicenseReasonLapse,
	LicenseReasonTrial,
	LicenseReasonTrialExtension,
	LicenseReasonTermRenewal,
	LicenseReasonContract,
	LicenseReasonMode,
	LicenseReasonTerms,
}
