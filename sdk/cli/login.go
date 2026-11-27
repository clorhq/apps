package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/clorhq/apps/sdk"
)

// flagDevice forces browser approval even when an account key is available.
const flagDevice = "device"

// NewLoginCommand signs the command line in to one instance, which issues the application's token.
func NewLoginCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "login <INSTANCE>",
		Short: "Sign the command line in to an instance",
		Long: "With an account key the sign-in is unattended: the key is exchanged with the API domain for a\n" +
			"signed identity, and only that identity reaches the instance. Without one, an approval page opens\n" +
			"in the browser and the command waits for Approve. INSTANCE is an ID, name or hostname; without an\n" +
			"account key it must be the hostname.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			ctx := cmd.Context()
			key, err := args.accountKey(cmd)
			if err != nil {
				return err
			}
			device, err := cmd.Flags().GetBool(flagDevice)
			if err != nil {
				return err
			}
			reference := strings.TrimRight(strings.TrimPrefix(strings.TrimSpace(positional[0]), "https://"), "/")
			hostname, instanceID := reference, ""
			if key != "" {
				client, err := args.accountClient(cmd)
				if err != nil {
					return err
				}
				summary, err := resolveInstance(ctx, client, reference)
				if err != nil {
					return err
				}
				instanceID = summary.ID
				if wait, _ := cmd.Flags().GetBool(flagWait); wait {
					if _, err := waitForReady(cmd, client, summary.ID); err != nil {
						return err
					}
					if summary, err = resolveInstance(ctx, client, summary.ID); err != nil {
						return err
					}
				}
				if summary.Hostname == "" || summary.URL == "" {
					return fmt.Errorf("instance %s is not ready yet. Wait for it with %s login %s --wait", summary.ID, args.Name, reference)
				}
				hostname = summary.Hostname
			} else if !strings.Contains(hostname, ".") {
				return fmt.Errorf("without an account key, pass the instance hostname. Or run %s account login --key ACCOUNT_KEY first", args.Name)
			}
			base := "https://" + hostname + args.terminalAuthPath()
			var result *sdk.TerminalAuthResult
			if key != "" && !device {
				result, err = signInWithKey(ctx, args, base, key)
			} else {
				result, err = signInWithApproval(cmd, args, base)
			}
			if err != nil {
				return err
			}
			if result.User == nil || result.Token == "" {
				return errors.New("the instance returned no token")
			}
			if instanceID == "" {
				instanceID = hostname
			}
			stored, err := args.loadSession()
			if err != nil {
				return err
			}
			stored.Instances[instanceID] = InstanceSession{
				InstanceID: instanceID,
				Hostname:   hostname,
				Token:      result.Token,
				User:       *result.User,
				SignedIn:   time.Now().UTC(),
			}
			if err := args.saveSession(stored); err != nil {
				return err
			}
			return writeRecords(cmd, "login", []record{{
				{"instance_id", instanceID},
				{"hostname", hostname},
				{"email", result.User.Email},
				{"owner", result.User.Owner},
			}})
		},
	}
	command.Flags().String(flagKey, "", "account key for unattended sign-in (or "+args.accountKeyEnvironment()+")")
	command.Flags().Bool(flagDevice, false, "approve in the browser even when an account key is available")
	command.Flags().Bool(flagNoBrowser, false, "print the approval address instead of opening it")
	command.Flags().Bool(flagWait, false, "wait until the instance is ready before signing in")
	command.Flags().Duration(flagTimeout, defaultWaitTimeout, "longest time to wait with --wait")
	addFormatFlag(command, args)
	return command
}

// signInWithKey exchanges the account key with the API domain and hands the identity token to the instance.
func signInWithKey(ctx context.Context, args *Args, base, key string) (*sdk.TerminalAuthResult, error) {
	client := args.httpClient()
	var start sdk.TerminalAuthStart
	if err := postJSON(ctx, client, base+sdk.TerminalAuthNonce, struct{}{}, &start); err != nil {
		return nil, err
	}
	accountClient, err := accountClientWithKey(args, key)
	if err != nil {
		return nil, err
	}
	idToken, err := accountClient.IdentityToken(ctx, start.InstanceID, start.Nonce)
	if err != nil {
		return nil, err
	}
	var result sdk.TerminalAuthResult
	if err := postJSON(ctx, client, base+sdk.TerminalAuthExchange, &sdk.TerminalAuthRequest{
		State:   start.State,
		IDToken: idToken,
	}, &result); err != nil {
		return nil, err
	}
	if result.Status != sdk.TerminalAuthApproved {
		return nil, fmt.Errorf("sign-in %s", result.Status)
	}
	return &result, nil
}

// signInWithApproval opens the approval page and polls until the user approves, cancels or the link expires.
func signInWithApproval(cmd *cobra.Command, args *Args, base string) (*sdk.TerminalAuthResult, error) {
	ctx := cmd.Context()
	client := args.httpClient()
	var start sdk.TerminalAuthStart
	if err := postJSON(ctx, client, base+sdk.TerminalAuthDevice, struct{}{}, &start); err != nil {
		return nil, err
	}
	if err := writeApproval(cmd, start.ApprovalURL); err != nil {
		return nil, err
	}
	args.openBrowser(cmd, start.ApprovalURL)
	interval := time.Duration(max(start.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		var result sdk.TerminalAuthResult
		if err := postJSON(ctx, client, base+sdk.TerminalAuthPoll, &sdk.TerminalAuthRequest{State: start.State}, &result); err != nil {
			return nil, err
		}
		switch result.Status {
		case sdk.TerminalAuthApproved:
			return &result, nil
		case sdk.TerminalAuthPending:
			if time.Now().After(deadline) {
				return nil, errors.New("the approval link expired. Run login again")
			}
		case sdk.TerminalAuthDenied:
			return nil, errors.New("sign-in was cancelled in the browser")
		default:
			return nil, errors.New("the approval link expired. Run login again")
		}
	}
}
