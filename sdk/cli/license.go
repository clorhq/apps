package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clorhq/apps/sdk/account"
)

// newLicenseCommand returns the license group: download and renew.
func newLicenseCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "license",
		Short: "Download and renew instance license files",
	}
	download := &cobra.Command{
		Use:   "download <INSTANCE>",
		Short: "Print an instance's current license file",
		Long:  "Prints the current license file. Downloading never changes the license.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			text, err := client.DownloadInstanceLicense(cmd.Context(), summary.ID)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), text)
			return err
		},
	}
	renew := &cobra.Command{
		Use:   "renew <INSTANCE>",
		Short: "Start a new free term and print its license file",
		Long:  "Renews the term of an instance on a free plan. Paid plans renew with payment, trials by extension and enterprise plans by contract.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			instance, err := client.ShowInstance(cmd.Context(), summary.ID)
			if err != nil {
				return err
			}
			text, err := client.RenewInstanceLicense(cmd.Context(), instance.ID, instance.License.Revision)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), text)
			return err
		},
	}
	for _, subcommand := range []*cobra.Command{download, renew} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		command.AddCommand(subcommand)
	}
	return command
}

// newModeCommand returns the mode group: switch.
func newModeCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "mode",
		Short: "Switch instances between the launcher and a license file",
	}
	var mode string
	switchMode := &cobra.Command{
		Use:   "switch <INSTANCE>",
		Short: "Switch an instance between the launcher and a license file",
		Long: "--mode offline runs the server with a license file: the launcher's keys stop working and its hostname stops resolving. " +
			"--mode managed prints a one-time install command, valid for 24 hours, that attaches a new launcher.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			mode = strings.TrimSpace(mode)
			if mode != string(account.InstanceModeManaged) && mode != string(account.InstanceModeOffline) {
				return errors.New("choose --mode managed for the launcher or --mode offline for a license file")
			}
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			switched, err := client.SwitchInstanceMode(cmd.Context(), summary.ID, account.InstanceMode(mode))
			if err != nil {
				return err
			}
			result := instanceRecord(&switched.Instance)
			result = append(result, field{"attach_command", switched.AttachCommand})
			return writeRecords(cmd, "instance", []record{result})
		},
	}
	switchMode.Flags().StringVar(&mode, "mode", "", "managed for the launcher, offline for a license file (managed|offline)")
	switchMode.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
	addFormatFlag(switchMode, args)
	command.AddCommand(switchMode)
	return command
}

// newDomainCommand returns the domain group: add and remove custom domains.
func newDomainCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "domain",
		Short: "Add and remove custom domains of instances",
	}
	add := &cobra.Command{
		Use:   "add <INSTANCE> <DOMAIN>",
		Short: "Add a domain you own to a managed instance",
		Long:  "Adds a custom domain. Point a CNAME record at the instance hostname; the application obtains the certificate.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			instance, err := client.AddInstanceDomain(cmd.Context(), summary.ID, positional[1])
			if err != nil {
				return err
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	remove := &cobra.Command{
		Use:   "remove <INSTANCE> <DOMAIN>",
		Short: "Remove a custom domain from an instance",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			instance, err := client.RemoveInstanceDomain(cmd.Context(), summary.ID, positional[1])
			if err != nil {
				return err
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	for _, subcommand := range []*cobra.Command{add, remove} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	return command
}
