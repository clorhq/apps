package model

import (
	"errors"
	"regexp"
	"strings"
)

const (
	DefaultInstanceNounSingular = "instance"
	DefaultInstanceNounPlural   = "instances"
	maximumNounCharacters       = 24
)

// InstanceNoun is the word an app uses for one team installation, such as server or database.
type InstanceNoun struct {
	Singular string `json:"singular"`
	Plural   string `json:"plural"`
}

var nounPattern = regexp.MustCompile(`^[a-z]+( [a-z]+)*$`)

// Normalize trims both forms and requires lowercase words separated by single spaces, or neither form.
func (n *InstanceNoun) Normalize() error {
	n.Singular = strings.TrimSpace(n.Singular)
	n.Plural = strings.TrimSpace(n.Plural)
	if n.Singular == "" && n.Plural == "" {
		return nil
	}
	if n.Singular == "" || n.Plural == "" {
		return errors.New("instance noun requires both singular and plural forms")
	}
	for _, word := range []string{n.Singular, n.Plural} {
		if len(word) > maximumNounCharacters || !nounPattern.MatchString(word) {
			return errors.New("instance noun forms use 1-24 lowercase letters with single spaces")
		}
	}
	return nil
}

// Noun returns the app's instance noun, defaulting to instance and instances.
func (b Branding) Noun() InstanceNoun {
	if b.InstanceNoun.Singular == "" || b.InstanceNoun.Plural == "" {
		return InstanceNoun{
			Singular: DefaultInstanceNounSingular,
			Plural:   DefaultInstanceNounPlural,
		}
	}
	return b.InstanceNoun
}

// SentenceCase capitalizes the first letter for headings and button labels.
func SentenceCase(text string) string {
	if text == "" {
		return ""
	}
	return strings.ToUpper(text[:1]) + text[1:]
}
