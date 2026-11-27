package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// NavigationPlacement selects the website menus that contain a link.
type NavigationPlacement string

const (
	navigationPlacementMessage = "navigation must be header, footer, both or none"

	NavigationHeader NavigationPlacement = "header"
	NavigationFooter NavigationPlacement = "footer"
	NavigationBoth   NavigationPlacement = "both"
	NavigationNone   NavigationPlacement = "none"
)

// UnmarshalJSON validates named menu placements.
func (placement *NavigationPlacement) UnmarshalJSON(navigationJSON []byte) error {
	var placementName string
	if err := json.Unmarshal(navigationJSON, &placementName); err != nil {
		return fmt.Errorf("%s: %w", navigationPlacementMessage, err)
	}
	selectedPlacement := NavigationPlacement(strings.TrimSpace(placementName))
	if selectedPlacement == "" {
		return errors.New(navigationPlacementMessage)
	}
	if err := selectedPlacement.ValidatePlacement(); err != nil {
		return err
	}
	*placement = selectedPlacement
	return nil
}

// MarshalJSON writes canonical placement names, with omitted page placement meaning none.
func (placement NavigationPlacement) MarshalJSON() ([]byte, error) {
	if placement == "" {
		placement = NavigationNone
	}
	if err := placement.ValidatePlacement(); err != nil {
		return nil, err
	}
	return json.Marshal(string(placement))
}

// ValidatePlacement rejects unsupported names while allowing an omitted setting.
func (placement NavigationPlacement) ValidatePlacement() error {
	switch placement {
	case "", NavigationHeader, NavigationFooter, NavigationBoth, NavigationNone:
		return nil
	default:
		return errors.New(navigationPlacementMessage)
	}
}

// IncludesMenu reports whether a link belongs in the requested menu.
func (placement NavigationPlacement) IncludesMenu(menu NavigationPlacement) bool {
	return placement == menu || placement == NavigationBoth
}

// WebsiteNavigation configures built-in link placement and optional footer columns.
type WebsiteNavigation struct {
	Packages     NavigationPlacement `json:"packages,omitempty"`
	Pricing      NavigationPlacement `json:"pricing,omitempty"`
	FooterGroups []FooterGroup       `json:"footer_groups,omitempty"`
}

// FooterGroup orders existing footer links beneath a heading using their exact URLs.
type FooterGroup struct {
	Title string   `json:"title"`
	Links []string `json:"links"`
}
