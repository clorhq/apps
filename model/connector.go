package model

import (
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	maximumConnectorTools        = 128
	ConnectorRegistrationPurpose = "connector_registration"
	ConnectorConnection          = "connector_connection"
	ConnectorCode                = "connector_code"
	ConnectorApproval            = "connector_approval"
	ConnectorRefresh             = "connector_refresh"
	ConnectorReviewerCredential  = "connector_reviewer"
	ConnectorLabel               = "mcp"
	ConnectorPrefix              = ConnectorLabel + "."
	ConnectorEndpoint            = "/mcp"
	ListInstancesTool            = "list_instances"
	OfflineScope                 = "offline_access"
	AccessTokenType              = "at+jwt"
	InstanceAccessLifetime       = time.Minute
	GatewayAccessLifetime        = 10 * time.Minute
)

// ConnectorHostname derives the gateway DNS name from the verified website.
func ConnectorHostname(website string) string { return ConnectorPrefix + website }

type Connector struct {
	DemoTeamID      string            `json:"demo_team_id,omitempty"`
	Clients         []ConnectorClient `json:"clients"`
	OptionalScopes  []string          `json:"optional_scopes,omitempty"`
	Scopes          map[string]string `json:"scopes"`
	OpenAIChallenge string            `json:"openai_challenge,omitempty"`
}

type ConnectorClient struct {
	ID                  string   `json:"client_id"`
	Name                string   `json:"client_name"`
	RedirectURIs        []string `json:"redirect_uris"`
	DynamicRegistration bool     `json:"dynamic_registration,omitempty"`
}

type ConnectorTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Scopes      []string        `json:"scopes"`
	ReadOnly    bool            `json:"read_only,omitempty"`
}

var connectorName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)
var connectorScope = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

// PermissionWording returns the consent text for a requested or granted scope.
func (c *Connector) PermissionWording(scope string) string {
	if scope == OfflineScope {
		return "Stay connected between sessions"
	}
	return c.Scopes[scope]
}

// Validate checks developer policy before enabling public-client authorization.
func (c *Connector) Validate() error {
	if len(c.Clients) == 0 || len(c.Scopes) == 0 || len(c.OpenAIChallenge) > 1_024 ||
		strings.ContainsAny(c.OpenAIChallenge, "\r\n") {
		return errors.New("invalid connector configuration")
	}
	for scope, wording := range c.Scopes {
		if !connectorScope.MatchString(scope) || scope == OfflineScope || strings.TrimSpace(wording) == "" {
			return errors.New("invalid connector permission")
		}
	}
	optional := map[string]bool{}
	for _, scope := range c.OptionalScopes {
		if optional[scope] || (scope != OfflineScope && c.Scopes[scope] == "") {
			return errors.New("optional permission must be a distinct declared scope or offline_access")
		}
		optional[scope] = true
	}
	clientIDs := map[string]bool{}
	for _, client := range c.Clients {
		if client.ID == "" || clientIDs[client.ID] || strings.TrimSpace(client.Name) == "" ||
			len(client.RedirectURIs) == 0 {
			return errors.New("invalid connector client")
		}
		clientIDs[client.ID] = true
		for _, redirect := range client.RedirectURIs {
			u, err := url.Parse(redirect)
			if err != nil || u.Hostname() == "" || u.User != nil || strings.Contains(redirect, "#") ||
				!(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost")) {
				return errors.New("invalid connector redirect URI")
			}
		}
	}
	return nil
}

// SameAuthorizationPolicy compares permissions and redirect allowlists while preserving client matching order.
func (c *Connector) SameAuthorizationPolicy(other *Connector) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.DemoTeamID == other.DemoTeamID &&
		maps.Equal(c.Scopes, other.Scopes) && equalConnectorAllowlist(c.OptionalScopes, other.OptionalScopes) &&
		slices.EqualFunc(c.Clients, other.Clients, func(a, b ConnectorClient) bool {
			return a.ID == b.ID && a.Name == b.Name && a.DynamicRegistration == b.DynamicRegistration &&
				equalConnectorAllowlist(a.RedirectURIs, b.RedirectURIs)
		})
}

// equalConnectorAllowlist compares the distinct values accepted by either policy.
func equalConnectorAllowlist(a, b []string) bool {
	a = slices.Sorted(slices.Values(a))
	b = slices.Sorted(slices.Values(b))
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// AllowsRedirect matches registered redirects exactly except for native loopback ports.
func (c *ConnectorClient) AllowsRedirect(address string) bool {
	candidate, err := url.Parse(address)
	if err != nil || candidate.User != nil || strings.Contains(address, "#") {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if registered == address {
			return true
		}
		u, err := url.Parse(registered)
		if err == nil && u.Scheme == "http" && u.Port() == "" && candidate.Scheme == "http" &&
			candidate.Hostname() == u.Hostname() &&
			candidate.Port() != "" {
			copyURL := *candidate
			copyURL.Host = u.Host
			if copyURL.String() == registered {
				return true
			}
		}
	}
	return false
}

// ValidateConnectorTools checks unique routable names, permission requirements and object input schemas.
func ValidateConnectorTools(tools []ConnectorTool) error {
	names := map[string]bool{ListInstancesTool: true}
	if len(tools) > maximumConnectorTools {
		return errors.New("too many connector tools")
	}
	for _, tool := range tools {
		var schema struct {
			Type       string                     `json:"type"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if names[tool.Name] || !connectorName.MatchString(tool.Name) || strings.TrimSpace(tool.Description) == "" ||
			len(tool.Scopes) == 0 ||
			json.Unmarshal(tool.InputSchema, &schema) != nil ||
			schema.Type != "object" ||
			schema.Properties["instance"] != nil {
			return errors.New("invalid connector tool definition")
		}
		for _, scope := range tool.Scopes {
			if !connectorScope.MatchString(scope) || scope == OfflineScope {
				return errors.New("invalid tool scope")
			}
		}
		names[tool.Name] = true
	}
	return nil
}

// ReleaseCatalog preserves the developer's MCP tool definitions, including extension fields.
type ReleaseCatalog struct {
	Tools []CatalogTool `json:"tools"`
}

// CatalogTool retains every field as JSON so the gateway never rounds schema numbers.
type CatalogTool map[string]json.RawMessage

// Name reads the MCP routing name of a catalog entry.
func (tool CatalogTool) Name() string {
	var name string
	if err := json.Unmarshal(tool["name"], &name); err != nil {
		return ""
	}
	return name
}

// Validate checks catalog structure and reserves the gateway's discovery tool.
func (catalog *ReleaseCatalog) Validate() error {
	if catalog.Tools == nil || len(catalog.Tools) > maximumConnectorTools {
		return errors.New("catalog requires a tools array with at most 128 entries")
	}
	names := map[string]bool{ListInstancesTool: true}
	for _, tool := range catalog.Tools {
		name := tool.Name()
		if !connectorName.MatchString(name) || names[name] {
			return errors.New("invalid, duplicate or reserved tool name")
		}
		names[name] = true
		for _, field := range []string{"inputSchema", "outputSchema"} {
			if field == "outputSchema" && tool[field] == nil {
				continue
			}
			var schema struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(tool[field], &schema); err != nil || schema.Type != "object" {
				return errors.New("tool schemas must describe an object")
			}
		}
		if annotations, ok := tool["annotations"]; ok {
			var hints map[string]json.RawMessage
			if err := json.Unmarshal(annotations, &hints); err != nil || hints == nil {
				return errors.New("tool annotations must be an object")
			}
		}
	}
	return nil
}
