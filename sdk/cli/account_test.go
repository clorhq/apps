package cli

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/clorhq/apps/sdk/account"
)

// changedFlags reports the listed flags as set on the command line.
func changedFlags(flags ...string) func(string) bool {
	return func(flag string) bool { return slices.Contains(flags, flag) }
}

// TestNewTeamUpdateOverlaysSetFlags keeps unset fields, trims set ones and sends the name and billing only when asked.
func TestNewTeamUpdateOverlaysSetFlags(t *testing.T) {
	current := &account.Team{
		Name: "Example Co",
		Slug: "example",
		Billing: account.BillingDetails{
			Name:  new("Example Co"),
			Email: new("billing@example.com"),
			Address: &account.BillingAddress{
				Line1:      new("1 Example Way"),
				City:       new("Example City"),
				PostalCode: new("00000"),
				Country:    new("US"),
			},
		},
	}
	update := newTeamUpdate(&newTeamUpdateArgs{
		Current: current,
		Changed: changedFlags(flagBillingEmail, flagAddressCity),
		Name:    "ignored because unset",
		Billing: &billingFlags{
			email: " ",
			city:  " Sample Town ",
			name:  "ignored because unset",
		},
	})
	require.Nil(t, update.Name, "the team name stays unchanged without --name")
	require.NotNil(t, update.Billing)
	require.Equal(t, "Example Co", *update.Billing.Name)
	require.Empty(t, *update.Billing.Email, "a set empty flag clears the field")
	require.Equal(t, "1 Example Way", *update.Billing.Address.Line1)
	require.Equal(t, "Sample Town", *update.Billing.Address.City)
	require.Equal(t, "US", *update.Billing.Address.Country)

	update = newTeamUpdate(&newTeamUpdateArgs{
		Current: current,
		Changed: changedFlags(flagTeamName),
		Name:    " Example Group ",
		Billing: &billingFlags{},
	})
	require.Equal(t, "Example Group", *update.Name)
	require.Nil(t, update.Billing, "billing details stay unchanged without billing flags")
}
