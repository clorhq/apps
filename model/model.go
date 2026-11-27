// Package model defines the versioned Apps resource contracts.
package model

import "time"

const ProtocolVersion = 2
const Unlimited = -1

type Branding struct {
	Navigation        WebsiteNavigation `json:"navigation,omitzero"`
	LogoWidth         int               `json:"logo_width,omitempty"`
	LogoHeight        int               `json:"logo_height,omitempty"`
	LogoDarkURL       string            `json:"logo_dark_url,omitempty"`
	LogoDarkWidth     int               `json:"logo_dark_width,omitempty"`
	LogoDarkHeight    int               `json:"logo_dark_height,omitempty"`
	LogoVariants      []ImageVariant    `json:"logo_variants,omitempty"`
	LogoDarkVariants  []ImageVariant    `json:"logo_dark_variants,omitempty"`
	SocialImageWidth  int               `json:"social_image_width,omitempty"`
	SocialImageHeight int               `json:"social_image_height,omitempty"`
	FaviconWidth      int               `json:"favicon_width,omitempty"`
	FaviconHeight     int               `json:"favicon_height,omitempty"`
	SocialImageURL    string            `json:"social_image_url,omitempty"`
	SocialImageAlt    string            `json:"social_image_alt,omitempty"`
	FaviconURL        string            `json:"favicon_url,omitempty"`
	ThemeColor        string            `json:"theme_color,omitempty"`
	TwitterSite       string            `json:"twitter_site,omitempty"`
	Locale            string            `json:"locale,omitempty"`
	Colors            Palette           `json:"colors,omitzero"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	WebsiteDomain     string            `json:"website_domain"`
	ServiceDomain     string            `json:"service_domain,omitempty"`
	SupportURL        string            `json:"support_url,omitempty"`
	LogoURL           string            `json:"logo_url,omitempty"`
	// InstanceNoun names the team's installation in every account page. Omitted means instance.
	InstanceNoun InstanceNoun `json:"instance_noun,omitzero"`
	// SocialLinks are external profiles, such as the project's GitHub, shown as icon
	// buttons in the website header and footer.
	SocialLinks []SocialLink `json:"social_links,omitempty"`
	// InstallURL is where a team admin learns to install the app, a site path such as
	// /install or an absolute HTTPS URL. Omitted means the homepage.
	InstallURL string `json:"install_url,omitempty"`
}

// SocialLink is one external profile link drawn as an icon button. Label is its
// accessible name and tooltip.
type SocialLink struct {
	Icon  string `json:"icon"`
	Href  string `json:"href"`
	Label string `json:"label"`
}
type Page struct {
	SocialImageWidth  int                 `json:"social_image_width,omitempty"`
	SocialImageHeight int                 `json:"social_image_height,omitempty"`
	SocialTitle       string              `json:"social_title,omitempty"`
	SocialDescription string              `json:"social_description,omitempty"`
	SocialImageURL    string              `json:"social_image_url,omitempty"`
	SocialImageAlt    string              `json:"social_image_alt,omitempty"`
	Slug              string              `json:"slug"`
	Title             string              `json:"title"`
	Description       string              `json:"description"`
	Markdown          string              `json:"markdown"`
	Navigation        NavigationPlacement `json:"navigation"`
	Screenshots       []Screenshot        `json:"screenshots"`
	Sections          []Section           `json:"sections,omitempty"`
	Blocks            []Block             `json:"blocks,omitempty"`
}

// Block is a structured page component rendered by the shared website template.
// Every text field is plain text; Markdown belongs in the page article and sections.
type Block struct {
	Align       string         `json:"align,omitempty"`
	Expanded    *bool          `json:"expanded,omitempty"`
	Tabs        []CodeTab      `json:"tabs,omitempty"`
	Wrap        *bool          `json:"wrap,omitempty"`
	Video       *Video         `json:"video,omitempty"`
	Images      []GalleryImage `json:"images,omitempty"`
	Columns     int            `json:"columns,omitempty"`
	AspectRatio string         `json:"aspect_ratio,omitempty"`
	Fit         string         `json:"fit,omitempty"`
	Type        string         `json:"type"`
	Anchor      string         `json:"anchor,omitempty"`
	Navigation  bool           `json:"navigation,omitempty"`
	Title       string         `json:"title,omitempty"`
	Subtitle    string         `json:"subtitle,omitempty"`
	Note        string         `json:"note,omitempty"`
	// Facts lists the labels and optional icons shown in a strip under the hero.
	Facts       []HeroFact  `json:"facts,omitempty"`
	Install     bool        `json:"install,omitempty"`
	PackageSlug string      `json:"package_slug,omitempty"`
	Actions     []Action    `json:"actions,omitempty"`
	Items       []BlockItem `json:"items,omitempty"`
	Screenshot  *Screenshot `json:"screenshot,omitempty"`
	// Prompt is the plain-text prompt of a prompt block, shown verbatim.
	Prompt string `json:"prompt,omitempty"`
	// Agents optionally selects and orders a prompt block's agents.
	Agents []string `json:"agents,omitempty"`
	// Enterprise adds a contact-sales card with an email capture to a pricing block.
	Enterprise *EnterpriseOffer `json:"enterprise,omitempty"`
}

// EnterpriseOffer is a pricing card without checkout. Its email capture posts to /sales.
type EnterpriseOffer struct {
	Name string `json:"name"`
	// PriceLabel is free text such as "From $15,000/yr".
	PriceLabel string   `json:"price_label,omitempty"`
	Features   []string `json:"features,omitempty"`
}

// GalleryImage is an external image with accessible text, caption, link and optional dark variant.
type GalleryImage struct {
	Width           int            `json:"width,omitempty"`
	Height          int            `json:"height,omitempty"`
	DarkWidth       int            `json:"dark_width,omitempty"`
	DarkHeight      int            `json:"dark_height,omitempty"`
	Variants        []ImageVariant `json:"variants,omitempty"`
	DarkVariants    []ImageVariant `json:"dark_variants,omitempty"`
	URL             string         `json:"url"`
	DarkURL         string         `json:"dark_url,omitempty"`
	AlternativeText string         `json:"alternative_text"`
	Caption         string         `json:"caption,omitempty"`
	Href            string         `json:"href,omitempty"`
}

// Action is a block link; the first action in a block is styled as primary.
type Action struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

// BlockItem is one feature, use case, diagram node, statistic, logo, bullet,
// step, or question inside a block.
type BlockItem struct {
	Width    int            `json:"width,omitempty"`
	Height   int            `json:"height,omitempty"`
	Variants []ImageVariant `json:"variants,omitempty"`
	Title    string         `json:"title"`
	Text     string         `json:"text,omitempty"`
	Icon     string         `json:"icon,omitempty"`
	URL      string         `json:"url,omitempty"`
}
type Section struct {
	Title    string `json:"title"`
	Markdown string `json:"markdown"`
}

// Screenshot is an external image with an optional variant shown in dark mode.
type Screenshot struct {
	Priority        bool           `json:"priority,omitempty"`
	Width           int            `json:"width,omitempty"`
	Height          int            `json:"height,omitempty"`
	DarkWidth       int            `json:"dark_width,omitempty"`
	DarkHeight      int            `json:"dark_height,omitempty"`
	Variants        []ImageVariant `json:"variants,omitempty"`
	DarkVariants    []ImageVariant `json:"dark_variants,omitempty"`
	URL             string         `json:"url"`
	DarkURL         string         `json:"dark_url,omitempty"`
	Caption         string         `json:"caption"`
	AlternativeText string         `json:"alternative_text"`
}
type Content struct {
	Branding Branding `json:"branding"`
	Pages    []Page   `json:"pages"`
	PlanIDs  []string `json:"plan_ids"`
}
type Plan struct {
	Name     string           `json:"name"`
	Currency string           `json:"currency"`
	Amount   int64            `json:"amount"`
	Interval string           `json:"interval"`
	Mode     string           `json:"mode"`
	Features map[string]bool  `json:"features"`
	Limits   map[string]int64 `json:"limits"`
	// Tagline says in a few words who the plan is for, such as "For production teams".
	Tagline string `json:"tagline,omitempty"`
	// OfflineLicenses allows offline instances and license file downloads on this plan.
	// When omitted at creation it resolves to true for yearly plans and false otherwise.
	OfflineLicenses *bool `json:"offline_licenses,omitempty"`
	// TermDays is the license term of an unpaid plan: free and trial plans require it.
	TermDays int `json:"term_days,omitempty"`
}

// License is the signed claim set for one instance's term. Apps signs facts only;
// each application decides its own warnings and grace around Starts and Expires.
type License struct {
	Version      int       `json:"version"`
	AppID        string    `json:"app_id"`
	InstanceID   string    `json:"instance_id"`
	PlanID       string    `json:"plan_id"`
	PlanName     string    `json:"plan_name"`
	PlanInterval string    `json:"plan_interval"`
	Revision     int64     `json:"revision"`
	Issued       time.Time `json:"issued"`
	Starts       time.Time `json:"starts"`
	Expires      time.Time `json:"expires"`
	// Renews is false once a cancellation is scheduled or when the term is unpaid.
	Renews    bool             `json:"renews"`
	Features  map[string]bool  `json:"features"`
	Limits    map[string]int64 `json:"limits"`
	PromoCode string           `json:"promo_code,omitempty"`
}
type SignedDocument struct {
	KeyID     string `json:"key_id"`
	Document  string `json:"document"`
	Signature string `json:"signature"`
}

type VerificationKeys struct {
	Version int               `json:"version"`
	AppID   string            `json:"app_id"`
	Keys    map[string]string `json:"keys"`
}
type Variant struct {
	Architecture  string            `json:"architecture"`
	Type          string            `json:"type"`
	ArchiveURL    string            `json:"archive_url,omitempty"`
	ArchiveSize   int64             `json:"archive_size,omitempty"`
	ArchiveDigest string            `json:"archive_digest,omitempty"`
	Executable    string            `json:"executable,omitempty"`
	Arguments     []string          `json:"arguments"`
	Environment   map[string]string `json:"environment"`
	Compose       string            `json:"compose,omitempty"`
	HealthURL     string            `json:"health_url"`
	Requirements  Requirements      `json:"requirements"`
}
type Requirements struct {
	Capabilities   []string `json:"capabilities"`
	Devices        []string `json:"devices"`
	Ports          []int    `json:"ports"`
	HostNetworking bool     `json:"host_networking"`
}
type Release struct {
	Tools     []ConnectorTool `json:"tools,omitempty"`
	Version   string          `json:"version"`
	Variants  []Variant       `json:"variants,omitempty"`
	Artifacts []Artifact      `json:"artifacts,omitempty"`
}
type InstanceConfiguration struct {
	Values           map[string]string `json:"values"`
	UpdateMode       string            `json:"update_mode"`
	Channel          string            `json:"channel"`
	UpdateVersion    string            `json:"update_version"`
	Timezone         string            `json:"timezone"`
	MaintenanceStart int               `json:"maintenance_start"`
	MaintenanceEnd   int               `json:"maintenance_end"`
}

// ImageVariant describes a developer-prepared responsive image without inspecting its pixels.
type ImageVariant struct {
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// Image submission bounds keep responsive sets small and dimension arithmetic bounded.
const (
	MaximumImageVariants  = 8
	MaximumImageDimension = 100_000
)
