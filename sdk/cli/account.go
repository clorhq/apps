package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/sdk/account"
)

// NewAccountCommand returns the account group: login, logout, key, card and invoice.
func NewAccountCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "account",
		Short: "Sign the command line in to a " + args.DisplayName + " team and manage its keys, cards and invoices",
	}
	command.AddCommand(
		newAccountLoginCommand(args),
		newAccountLogoutCommand(args),
		newKeyCommand(args),
		newCardCommand(args),
		newInvoiceCommand(args),
	)
	return command
}

// NewTeamCommand returns the team group: show, update and member.
func NewTeamCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "team",
		Short: "Show and change the account key's team and its members",
	}
	command.AddCommand(
		newTeamShowCommand(args),
		newTeamUpdateCommand(args),
		newMemberCommand(args),
	)
	return command
}

// newAccountLoginCommand stores an account key after checking it.
func newAccountLoginCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "login",
		Short: "Sign the command line in to a team with an account key",
		Long: "Stores an account key for later commands after checking it. A team admin creates the key on the\n" +
			"team's Keys page. Without --key, the key comes from " + args.accountKeyEnvironment() + "; with neither,\n" +
			"the teams page opens to choose a team.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := cmd.Flags().GetString(flagKey)
			if err != nil {
				return err
			}
			key = strings.TrimSpace(key)
			if key == "" {
				key = strings.TrimSpace(os.Getenv(args.accountKeyEnvironment()))
			}
			if key == "" {
				teamsPage := strings.TrimRight(args.WebsiteOrigin, "/") + model.RouteTeams
				args.openBrowser(cmd, teamsPage)
				return fmt.Errorf(
					"open a team at %s and create an account key on its Keys page, then run %s account login --key ACCOUNT_KEY or set %s",
					teamsPage,
					args.Name,
					args.accountKeyEnvironment(),
				)
			}
			stored, err := args.loadSession()
			if err != nil {
				return err
			}
			client, err := account.NewClient(&account.NewClientArgs{
				APIOrigin:  args.APIOrigin,
				Key:        key,
				HTTPClient: args.httpClient(),
			})
			if err != nil {
				return err
			}
			team, err := client.ShowTeam(cmd.Context())
			if err != nil {
				return err
			}
			stored.AccountKey = key
			if err := args.saveSession(stored); err != nil {
				return err
			}
			return writeRecords(cmd, "login", []record{{
				{"team", team.Name},
				{"slug", team.Slug},
			}})
		},
	}
	command.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
	command.Flags().Bool(flagNoBrowser, false, "print the teams page address instead of opening it")
	addFormatFlag(command, args)
	return command
}

// newAccountLogoutCommand removes the stored account key and instance sign-ins.
func newAccountLogoutCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored account key and instance sign-ins",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stored, err := args.loadSession()
			if err != nil {
				return err
			}
			instances := len(stored.Instances)
			if err := args.saveSession(&session{Instances: map[string]InstanceSession{}}); err != nil {
				return err
			}
			return writeRecords(cmd, "logout", []record{{{"instances", instances}}})
		},
	}
	addFormatFlag(command, args)
	return command
}

// teamRecord formats a team for output.
func teamRecord(team *account.Team) record {
	return record{
		{"id", team.ID},
		{"name", team.Name},
		{"slug", team.Slug},
		{"billing_name", optionalString(team.Billing.Name)},
		{"billing_email", optionalString(team.Billing.Email)},
	}
}

// newTeamShowCommand prints the team's name, slug and billing details.
func newTeamShowCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "show",
		Short: "Show the team and its billing details",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			team, err := client.ShowTeam(cmd.Context())
			if err != nil {
				return err
			}
			return writeRecords(cmd, "team", []record{teamRecord(team)})
		},
	}
	command.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
	addFormatFlag(command, args)
	return command
}

// memberRecord formats a member for output.
func memberRecord(member *account.Member) record {
	return record{
		{"id", member.ID},
		{"email", member.Email},
		{"role", string(member.Role)},
		{"owner", member.Owner},
		{"created", member.Created},
	}
}

// invitationRecord formats a pending invitation for output.
func invitationRecord(invitation *account.Invitation) record {
	return record{
		{"id", invitation.ID},
		{"email", invitation.Email},
		{"role", string(invitation.Role)},
		{"expires", invitation.Expires},
	}
}

// newMemberCommand returns the member group: list, invite, role and remove.
func newMemberCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "member",
		Short: "Manage the team's members and invitations",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List members and pending invitations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			members, err := client.ListMembers(cmd.Context())
			if err != nil {
				return err
			}
			records := []record{}
			for _, member := range members.Items {
				records = append(records, memberRecord(&member))
			}
			if err := writeRecords(cmd, "member", records); err != nil {
				return err
			}
			invitations := []record{}
			for _, invitation := range members.Invitations {
				invitations = append(invitations, invitationRecord(&invitation))
			}
			return writeRecords(cmd, "invitation", invitations)
		},
	}
	var inviteRole string
	invite := &cobra.Command{
		Use:   "invite <EMAIL>",
		Short: "Invite an email address to the team and email the invitation link",
		Long: "The invitation works for seven days, and only a person signed in with that verified email can\n" +
			"accept it. Admins can do everything; billing members handle invoices and cards.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			invitation, err := client.InviteMember(cmd.Context(), strings.TrimSpace(positional[0]), account.Role(strings.TrimSpace(inviteRole)))
			if err != nil {
				return err
			}
			return writeRecords(cmd, "invitation", []record{invitationRecord(invitation)})
		},
	}
	invite.Flags().StringVar(&inviteRole, "role", string(account.RoleAdmin), "role of the invited member (admin|billing)")
	role := &cobra.Command{
		Use:   "role <MEMBER_ID> <ROLE>",
		Short: "Change a member's role to admin or billing",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			member, err := client.ChangeMemberRole(cmd.Context(), strings.TrimSpace(positional[0]), account.Role(strings.TrimSpace(positional[1])))
			if err != nil {
				return err
			}
			return writeRecords(cmd, "member", []record{memberRecord(member)})
		},
	}
	remove := &cobra.Command{
		Use:   "remove <MEMBER_ID>",
		Short: "Remove a member and revoke the account keys they created",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			memberID := strings.TrimSpace(positional[0])
			if err := client.RemoveMember(cmd.Context(), memberID); err != nil {
				return err
			}
			return writeRecords(cmd, "member", []record{{
				{"id", memberID},
				{"removed", true},
			}})
		},
	}
	for _, subcommand := range []*cobra.Command{list, invite, role, remove} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	return command
}

// keyRecord formats a key for output.
func keyRecord(key *account.Key) record {
	return record{
		{"id", key.ID},
		{"type", string(key.Type)},
		{"name", key.Name},
		{"labels", model.Labels(key.Labels).String()},
		{"preview", key.Preview},
		{"reusable", key.Reusable},
		{"ephemeral", key.Ephemeral},
		{"expires", key.Expires},
		{"last_used", key.LastUsed},
		{"revoked", key.Revoked},
	}
}

// newKeyCommand returns the key group: list, create and revoke.
func newKeyCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "key",
		Short: "Manage account and install keys",
	}
	var labelSelector string
	list := &cobra.Command{
		Use:   "list",
		Short: "List account and install keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			keys, err := client.ListKeys(cmd.Context(), &account.ListArgs{LabelSelector: labelSelector})
			if err != nil {
				return err
			}
			records := []record{}
			for _, key := range keys {
				records = append(records, keyRecord(&key))
			}
			return writeRecords(cmd, "key", records)
		},
	}
	list.Flags().StringVar(&labelSelector, "label", "", "label selector such as role=edge,!pinned")
	var keyType, name string
	var labels []string
	var expires time.Duration
	var reusable, ephemeral bool
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an account or install key and print its token once",
		Long: "Account keys do everything a team admin can. Install keys only install and claim\n" +
			"instances, for scripts such as install.sh --key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			keyLabels, err := model.ParseLabels(labels)
			if err != nil {
				return err
			}
			createArgs := &account.CreateKeyArgs{
				Labels:    keyLabels,
				Type:      strings.TrimSpace(keyType),
				Name:      strings.TrimSpace(name),
				Reusable:  reusable,
				Ephemeral: ephemeral,
			}
			if expires > 0 {
				createArgs.Expires = new(time.Now().Add(expires))
			}
			created, err := client.CreateKey(cmd.Context(), createArgs)
			if err != nil {
				return err
			}
			return writeRecords(cmd, "key", []record{append(keyRecord(&created.Key), field{"token", created.Token})})
		},
	}
	create.Flags().StringVar(&keyType, "type", model.KeyTypeAccount, "key type (account|install)")
	create.Flags().StringVar(&name, "name", "", "key name")
	create.Flags().DurationVar(&expires, "expires", 0, "lifetime such as 720h, never expiring by default")
	create.Flags().BoolVar(&reusable, "reusable", false, "let an install key install any number of instances")
	create.Flags().BoolVar(&ephemeral, "ephemeral", false, "remove instances installed with this key after an hour offline")
	create.Flags().StringArrayVar(&labels, "label", nil, "label such as role=edge or pinned, repeatable; instances installed with an install key copy them")
	revoke := &cobra.Command{
		Use:   "revoke <KEY_ID>",
		Short: "Revoke a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			key, err := client.RevokeKey(cmd.Context(), strings.TrimSpace(positional[0]))
			if err != nil {
				return err
			}
			return writeRecords(cmd, "key", []record{keyRecord(key)})
		},
	}
	for _, subcommand := range []*cobra.Command{list, create, revoke} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	command.AddCommand(newLabelCommand(args, "key", "<KEY_ID>", func(cmd *cobra.Command, client *account.Client, reference string, change *account.LabelChange) error {
		key, err := client.UpdateKeyLabels(cmd.Context(), strings.TrimSpace(reference), change)
		if err != nil {
			return err
		}
		return writeRecords(cmd, "key", []record{keyRecord(key)})
	}))
	return command
}

// newInvoiceCommand returns the invoice group, which lists recent invoices with their links.
func newInvoiceCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "invoice",
		Short: "List the team's invoices",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List recent invoices with their hosted page and PDF links",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			invoices, err := client.ListInvoices(cmd.Context())
			if err != nil {
				return err
			}
			records := []record{}
			for _, invoice := range invoices {
				records = append(records, record{
					{"id", invoice.ID},
					{"number", invoice.Number},
					{"created", invoice.Created},
					{"total", invoice.Total},
					{"currency", invoice.Currency},
					{"status", string(invoice.Status)},
					{"hosted_url", invoice.HostedURL},
					{"pdf_url", invoice.PDFURL},
				})
			}
			return writeRecords(cmd, "invoice", records)
		},
	}
	command.AddCommand(list)
	return command
}

// newCardCommand returns the card group, which adds a default card through a hosted form.
func newCardCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "card",
		Short: "Add a card for invoices and renewals",
	}
	add := &cobra.Command{
		Use:   "add",
		Short: "Open the hosted card form that saves your default card",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			cardURL, err := client.CreateCardCheckout(cmd.Context())
			if err != nil {
				return err
			}
			args.openBrowser(cmd, cardURL)
			return writeRecords(cmd, "card", []record{{{"url", cardURL}}})
		},
	}
	add.Flags().Bool(flagNoBrowser, false, "print the card form address instead of opening it")
	add.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
	addFormatFlag(add, args)
	command.AddCommand(add)
	return command
}

// Billing detail flags of team update.
const (
	flagBillingName       = "billing-name"
	flagBillingEmail      = "billing-email"
	flagAddressLine1      = "address-line1"
	flagAddressLine2      = "address-line2"
	flagAddressCity       = "address-city"
	flagAddressRegion     = "address-region"
	flagAddressPostalCode = "address-postal-code"
	flagAddressCountry    = "address-country"
)

// billingFlags are the billing detail flags of team update.
type billingFlags struct {
	name       string
	email      string
	line1      string
	line2      string
	city       string
	region     string
	postalCode string
	country    string
}

// newTeamUpdateCommand changes the team name and billing details, keeping every field whose flag is unset.
func newTeamUpdateCommand(args *Args) *cobra.Command {
	var teamName string
	var details billingFlags
	command := &cobra.Command{
		Use:   "update",
		Short: "Change the team name and billing details",
		Long: "Only the fields whose flags are set change; the rest keep their current values.\n" +
			"An empty value clears a billing field.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			current, err := client.ShowTeam(cmd.Context())
			if err != nil {
				return err
			}
			update := newTeamUpdate(&newTeamUpdateArgs{
				Current: current,
				Changed: cmd.Flags().Changed,
				Name:    teamName,
				Billing: &details,
			})
			updated, err := client.UpdateTeam(cmd.Context(), update)
			if err != nil {
				return err
			}
			return writeRecords(cmd, "team", []record{teamRecord(updated)})
		},
	}
	command.Flags().StringVar(&teamName, flagTeamName, "", "team name")
	command.Flags().StringVar(&details.name, flagBillingName, "", "name on invoices")
	command.Flags().StringVar(&details.email, flagBillingEmail, "", "email for invoices, the owner's sign-in email when empty")
	command.Flags().StringVar(&details.line1, flagAddressLine1, "", "street address")
	command.Flags().StringVar(&details.line2, flagAddressLine2, "", "apartment, suite or unit")
	command.Flags().StringVar(&details.city, flagAddressCity, "", "city")
	command.Flags().StringVar(&details.region, flagAddressRegion, "", "state or region")
	command.Flags().StringVar(&details.postalCode, flagAddressPostalCode, "", "postal code")
	command.Flags().StringVar(&details.country, flagAddressCountry, "", "two-letter country code such as US")
	command.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
	addFormatFlag(command, args)
	return command
}

// newTeamUpdateArgs are the current team and the flags team update was given.
type newTeamUpdateArgs struct {
	Current *account.Team
	// Changed reports whether a flag was set on the command line.
	Changed func(flag string) bool
	Name    string
	Billing *billingFlags
}

// newTeamUpdate overlays the set flags on the current team, so one update never clears a
// field whose flag was not set. The name and billing details are sent only when their flags are set.
func newTeamUpdate(args *newTeamUpdateArgs) *account.TeamUpdate {
	current := args.Current
	update := &account.TeamUpdate{}
	if args.Changed(flagTeamName) {
		update.Name = new(strings.TrimSpace(args.Name))
	}
	billingFlagSet := false
	for _, flag := range []string{
		flagBillingName,
		flagBillingEmail,
		flagAddressLine1,
		flagAddressLine2,
		flagAddressCity,
		flagAddressRegion,
		flagAddressPostalCode,
		flagAddressCountry,
	} {
		billingFlagSet = billingFlagSet || args.Changed(flag)
	}
	if !billingFlagSet {
		return update
	}
	// overlay replaces a current value with its trimmed flag value when the flag was set.
	overlay := func(flag, currentValue, flagValue string) *string {
		if args.Changed(flag) {
			return new(strings.TrimSpace(flagValue))
		}
		return new(currentValue)
	}
	address := account.BillingAddress{}
	if current.Billing.Address != nil {
		address = *current.Billing.Address
	}
	billing := args.Billing
	update.Billing = &account.BillingDetails{
		Name:  overlay(flagBillingName, optionalString(current.Billing.Name), billing.name),
		Email: overlay(flagBillingEmail, optionalString(current.Billing.Email), billing.email),
		Address: &account.BillingAddress{
			Line1:      overlay(flagAddressLine1, optionalString(address.Line1), billing.line1),
			Line2:      overlay(flagAddressLine2, optionalString(address.Line2), billing.line2),
			City:       overlay(flagAddressCity, optionalString(address.City), billing.city),
			Region:     overlay(flagAddressRegion, optionalString(address.Region), billing.region),
			PostalCode: overlay(flagAddressPostalCode, optionalString(address.PostalCode), billing.postalCode),
			Country:    overlay(flagAddressCountry, strings.ToUpper(optionalString(address.Country)), strings.ToUpper(billing.country)),
		},
	}
	return update
}

// optionalString is an optional response string, empty when absent.
func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
