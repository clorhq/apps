package model

import (
	"fmt"
	"strings"
)

// Palette supplies optional semantic colors for a published website.
type Palette struct {
	Primary    string `json:"primary,omitempty"`
	OnPrimary  string `json:"on_primary,omitempty"`
	Accent     string `json:"accent,omitempty"`
	Background string `json:"background,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Text       string `json:"text,omitempty"`
	MutedText  string `json:"muted_text,omitempty"`
	Border     string `json:"border,omitempty"`
	Focus      string `json:"focus,omitempty"`
}

// Normalize trims palette inputs and accepts only six-digit hexadecimal colors.
func (p *Palette) Normalize() error {
	for name, color := range map[string]*string{
		"primary": &p.Primary, "on_primary": &p.OnPrimary, "accent": &p.Accent,
		"background": &p.Background, "surface": &p.Surface, "text": &p.Text,
		"muted_text": &p.MutedText, "border": &p.Border, "focus": &p.Focus,
	} {
		*color = strings.ToLower(strings.TrimSpace(*color))
		if *color == "" {
			continue
		}
		if len(*color) != 7 || (*color)[0] != '#' {
			return fmt.Errorf("branding color %s requires a six-digit hex color", name)
		}
		for _, digit := range (*color)[1:] {
			if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
				return fmt.Errorf("branding color %s requires a six-digit hex color", name)
			}
		}
	}
	return nil
}
