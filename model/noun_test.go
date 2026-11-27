package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInstanceNoun trims both forms, requires them together and defaults to instance.
func TestInstanceNoun(t *testing.T) {
	require.Equal(t, InstanceNoun{Singular: "instance", Plural: "instances"}, Branding{}.Noun())
	noun := InstanceNoun{Singular: "  database server ", Plural: " database servers"}
	require.NoError(t, noun.Normalize())
	require.Equal(t, InstanceNoun{Singular: "database server", Plural: "database servers"}, noun)
	require.Equal(t, noun, Branding{InstanceNoun: noun}.Noun())
	empty := InstanceNoun{Singular: " ", Plural: ""}
	require.NoError(t, empty.Normalize())
	require.Equal(t, InstanceNoun{}, empty)
	for _, invalid := range []InstanceNoun{
		{Singular: "server"},
		{Plural: "servers"},
		{Singular: "Server", Plural: "Servers"},
		{Singular: "data  base", Plural: "data bases"},
		{Singular: "server1", Plural: "servers"},
		{Singular: "an-server", Plural: "servers"},
		{Singular: strings.Repeat("a", 25), Plural: "servers"},
	} {
		require.Error(t, invalid.Normalize(), invalid)
	}
	require.NoError(t, (&InstanceNoun{Singular: strings.Repeat("a", 24), Plural: "b"}).Normalize())
	require.Equal(t, "Database servers", SentenceCase("database servers"))
}
