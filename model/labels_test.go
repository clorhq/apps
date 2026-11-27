package model

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseLabels accepts key=value and bare keys and rejects invalid syntax and counts.
func TestParseLabels(t *testing.T) {
	labels, err := ParseLabels([]string{" role=backup ", "pinned", "site = berlin", ""})
	require.NoError(t, err)
	require.Equal(t, Labels{"role": "backup", "pinned": "", "site": "berlin"}, labels)
	require.Equal(t, "pinned role=backup site=berlin", labels.String())
	for _, invalid := range [][]string{
		{"Role=backup"},
		{"role=Backup"},
		{"team/role=backup"},
		{"-role"},
		{"role=" + strings.Repeat("a", MaximumLabelCharacters+1)},
		{"=value"},
	} {
		_, err := ParseLabels(invalid)
		require.ErrorIs(t, err, ErrInvalidLabels, invalid)
	}
	many := []string{}
	for i := range MaximumLabels + 1 {
		many = append(many, "label"+strings.Repeat("x", i))
	}
	_, err = ParseLabels(many)
	require.ErrorIs(t, err, ErrInvalidLabels)

	_, err = ParseLabels([]string{"Role"})
	labelError, ok := errors.AsType[*LabelError](err)
	require.True(t, ok)
	require.Equal(t, `label "Role" needs 1 to 63 lowercase letters, digits, dots, hyphens or underscores`, labelError.Message)
	_, err = ParseLabels([]string{strings.Repeat("a", MaximumLabelCharacters)})
	require.NoError(t, err, "the maximum length is allowed")
}

// TestLabelSelector matches presence, absence, equality and inequality, all of which must hold.
func TestLabelSelector(t *testing.T) {
	labels := Labels{"role": "backup", "pinned": ""}
	for selector, matches := range map[string]bool{
		"":                         true,
		"role":                     true,
		"!role":                    false,
		"role=backup":              true,
		"role=archive":             false,
		"role!=archive":            true,
		"role!=backup":             false,
		"site!=berlin":             true,
		"pinned, role=backup":      true,
		"pinned,role=backup,!site": true,
		"pinned,role=backup,site":  false,
	} {
		parsed, err := ParseLabelSelector(selector)
		require.NoError(t, err, selector)
		require.Equal(t, matches, parsed.Matches(labels), selector)
	}
	for _, invalid := range []string{"Role", "!", "role==backup", "team/role"} {
		_, err := ParseLabelSelector(invalid)
		require.ErrorIs(t, err, ErrInvalidLabels, invalid)
	}
}
