package model

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConnectorPolicyPrecedence allows equivalent scope and redirect sets while preserving first-match client order.
func TestConnectorPolicyPrecedence(t *testing.T) {
	policy := &Connector{
		OptionalScopes: []string{"read", "write"},
		Clients: []ConnectorClient{
			{ID: "first", RedirectURIs: []string{"https://example.com/a", "https://example.com/b"}},
			{ID: "second", RedirectURIs: []string{"https://example.com/b"}},
		},
	}
	edited := *policy
	edited.OptionalScopes = []string{"write", "read"}
	edited.Clients = slices.Clone(policy.Clients)
	edited.Clients[0].RedirectURIs = []string{"https://example.com/b", "https://example.com/a", "https://example.com/b"}
	require.True(t, policy.SameAuthorizationPolicy(&edited))
	slices.Reverse(edited.Clients)
	require.False(t, policy.SameAuthorizationPolicy(&edited))
}
