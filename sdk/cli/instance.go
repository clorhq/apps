package cli

import (
	"errors"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clorhq/apps/model"
	"github.com/clorhq/apps/sdk/account"
)

// NewInstanceCommand returns the instance group: list, show, claim, remove, plan and checkout.
func NewInstanceCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "instance",
		Short: "Manage your " + args.DisplayName + " instances",
	}
	var labelSelector string
	list := &cobra.Command{
		Use:   "list",
		Short: "List your instances",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			instances, err := client.ListInstances(cmd.Context(), &account.ListArgs{LabelSelector: labelSelector})
			if err != nil {
				return err
			}
			records := []record{}
			for _, instance := range instances {
				records = append(records, record{
					{"id", instance.ID},
					{"name", instance.Name},
					{"hostname", instance.Hostname},
					{"status", string(instance.Status)},
					{"plan_id", instance.PlanID},
					{"labels", model.Labels(instance.Labels).String()},
					{"url", instance.URL},
				})
			}
			return writeRecords(cmd, "instance", records)
		},
	}
	list.Flags().StringVar(&labelSelector, "label", "", "label selector such as role=backup,!pinned")
	show := &cobra.Command{
		Use:   "show <INSTANCE>",
		Short: "Show an instance by ID, name or hostname",
		Long:  "Shows plan, license, readiness and the application's report. With --wait, waits until the instance is ready.",
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
			var instance *account.Instance
			if wait, _ := cmd.Flags().GetBool(flagWait); wait {
				instance, err = waitForReady(cmd, client, summary.ID)
			} else {
				instance, err = client.ShowInstance(cmd.Context(), summary.ID)
			}
			if err != nil {
				return err
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	show.Flags().Bool(flagWait, false, "wait until the instance is ready")
	show.Flags().Duration(flagTimeout, defaultWaitTimeout, "longest time to wait with --wait")
	var name, planID string
	claim := &cobra.Command{
		Use:   "claim <CLAIM_URL>",
		Short: "Claim an installed instance with the claim URL the installer printed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			claimURL, err := url.Parse(strings.TrimSpace(positional[0]))
			if err != nil {
				return err
			}
			instance, err := client.ClaimInstance(cmd.Context(), &account.ClaimArgs{
				InstanceID: claimURL.Query().Get("instance"),
				ClaimToken: claimURL.Query().Get("token"),
				Name:       strings.TrimSpace(name),
				PlanID:     strings.TrimSpace(planID),
			})
			if err != nil {
				return err
			}
			if wait, _ := cmd.Flags().GetBool(flagWait); wait {
				if instance, err = waitForReady(cmd, client, instance.ID); err != nil {
					return err
				}
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	claim.Flags().StringVar(&name, "name", "", "instance name, a lowercase hostname label")
	claim.Flags().StringVar(&planID, "plan", "", "plan ID, defaulting to the free plan")
	claim.Flags().Bool(flagWait, false, "wait until the instance is ready")
	claim.Flags().Duration(flagTimeout, defaultWaitTimeout, "longest time to wait with --wait")
	remove := &cobra.Command{
		Use:   "remove <INSTANCE>",
		Short: "Permanently remove an instance",
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
			instance, err := client.RevokeInstance(cmd.Context(), summary.ID)
			if err != nil {
				return err
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	var offline bool
	var createName string
	create := &cobra.Command{
		Use:   "create",
		Short: "Add a server that runs with a license file",
		Long:  "Adds a server that runs with a license file and never contacts the service. Download the file with instance license download.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !offline {
				return errors.New("instances that run the launcher are added by installing it. Use --offline to add a server with a license file")
			}
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			instance, err := client.CreateOfflineInstance(cmd.Context(), createName)
			if err != nil {
				return err
			}
			return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
		},
	}
	create.Flags().BoolVar(&offline, "offline", false, "add a server that runs with a license file")
	create.Flags().StringVar(&createName, "name", "", "instance name, a lowercase hostname label")
	for _, subcommand := range []*cobra.Command{list, show, claim, remove, create} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	command.AddCommand(newPlanCommand(args))
	command.AddCommand(newLicenseCommand(args))
	command.AddCommand(newModeCommand(args))
	command.AddCommand(newDomainCommand(args))
	command.AddCommand(newLabelCommand(args, "instance", "<INSTANCE>", func(cmd *cobra.Command, client *account.Client, reference string, change *account.LabelChange) error {
		summary, err := resolveInstance(cmd.Context(), client, reference)
		if err != nil {
			return err
		}
		instance, err := client.UpdateInstanceLabels(cmd.Context(), summary.ID, change)
		if err != nil {
			return err
		}
		return writeRecords(cmd, "instance", []record{instanceRecord(instance)})
	}))
	return command
}

// labelUpdate applies a label change to one resource and prints it.
type labelUpdate func(cmd *cobra.Command, client *account.Client, reference string, change *account.LabelChange) error

// newLabelCommand returns a label group with set and remove for one resource type.
func newLabelCommand(args *Args, resource, placeholder string, update labelUpdate) *cobra.Command {
	command := &cobra.Command{
		Use:   "label",
		Short: "Set and remove " + resource + " labels",
	}
	set := &cobra.Command{
		Use:     "set " + placeholder + " <LABEL>...",
		Short:   "Set labels such as role=backup or pinned, replacing values of the same keys",
		Example: "  " + args.Name + " " + resource + " label set office-backup role=backup pinned",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			labels, err := model.ParseLabels(positional[1:])
			if err != nil {
				return err
			}
			return update(cmd, client, positional[0], &account.LabelChange{Set: labels})
		},
	}
	remove := &cobra.Command{
		Use:     "remove " + placeholder + " <KEY>...",
		Short:   "Remove labels by key",
		Example: "  " + args.Name + " " + resource + " label remove office-backup pinned",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			return update(cmd, client, positional[0], &account.LabelChange{Remove: positional[1:]})
		},
	}
	for _, subcommand := range []*cobra.Command{set, remove} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	return command
}

// instanceRecord formats an instance for output.
func instanceRecord(instance *account.Instance) record {
	planName := ""
	if instance.Plan != nil {
		planName = instance.Plan.Name
	}
	return record{
		{"id", instance.ID},
		{"name", instance.Name},
		{"hostname", instance.Hostname},
		{"status", string(instance.Status)},
		{"mode", string(instance.Mode)},
		{"plan_id", instance.PlanID},
		{"plan", planName},
		{"labels", model.Labels(instance.Labels).String()},
		{"ready", instance.Readiness.Ready},
		{"url", instance.URL},
		{"version", instance.Version},
		{"reported_status", instance.Report.ReportedStatus},
		{"upgrade_recommended", instance.Report.UpgradeRecommended},
		{"revoked", instance.Revoked},
	}
}

// newPlanCommand returns the plan group: list, change and cancel.
func newPlanCommand(args *Args) *cobra.Command {
	command := &cobra.Command{
		Use:   "plan",
		Short: "List and change instance plans",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the plans you can choose",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			plans, err := client.ListPlans(cmd.Context())
			if err != nil {
				return err
			}
			records := []record{}
			for _, plan := range plans {
				records = append(records, record{
					{"id", plan.ID},
					{"name", plan.Name},
					{"amount", plan.Amount},
					{"currency", plan.Currency},
					{"interval", string(plan.Interval)},
				})
			}
			return writeRecords(cmd, "plan", records)
		},
	}
	var planID, promoCode string
	change := &cobra.Command{
		Use:   "change <INSTANCE>",
		Short: "Change an instance's plan",
		Long: "The latest choice wins. A payment_required result opens the payment page. Higher-priced plans and " +
			"moves from monthly to yearly apply now; cheaper plans apply at the end of the paid period. Choosing a " +
			"free plan cancels the paid plan at the end of its paid period, and choosing the current plan keeps it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positional []string) error {
			client, err := args.accountClient(cmd)
			if err != nil {
				return err
			}
			summary, err := resolveInstance(cmd.Context(), client, positional[0])
			if err != nil {
				return err
			}
			changed, err := client.ChangePlan(cmd.Context(), summary.ID, strings.TrimSpace(planID), strings.TrimSpace(promoCode))
			if err != nil {
				return err
			}
			if changed.PaymentURL != "" {
				args.openBrowser(cmd, changed.PaymentURL)
			}
			changeRecord := record{
				{"result", string(changed.Result)},
				{"payment_url", changed.PaymentURL},
			}
			if changed.Effective != nil {
				changeRecord = append(changeRecord, field{"effective", *changed.Effective})
			}
			return writeRecords(cmd, "plan_change", []record{append(changeRecord, instanceRecord(&changed.Instance)...)})
		},
	}
	change.Flags().StringVar(&planID, "plan", "", "plan ID from plan list")
	change.Flags().StringVar(&promoCode, "promo-code", "", "promo code for a new subscription")
	change.Flags().Bool(flagNoBrowser, false, "print the payment address instead of opening it")
	var previewPlanID string
	preview := &cobra.Command{
		Use:   "preview <INSTANCE>",
		Short: "Show what changing an instance's plan would do",
		Long:  "Shows the result, when it takes effect and, for a change charged now, the amount due including tax in minor currency units.",
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
			previewed, err := client.PreviewPlan(cmd.Context(), summary.ID, strings.TrimSpace(previewPlanID))
			if err != nil {
				return err
			}
			previewRecord := record{
				{"instance_id", summary.ID},
				{"result", string(previewed.Result)},
				{"plan_id", previewed.Plan.ID},
				{"current_plan_id", previewed.CurrentPlan.ID},
				{"promo_allowed", previewed.PromoAllowed},
			}
			if previewed.Charge != nil {
				previewRecord = append(previewRecord,
					field{"amount_due", previewed.Charge.AmountDue},
					field{"tax", previewed.Charge.Tax},
					field{"currency", previewed.Charge.Currency},
				)
			}
			if previewed.Effective != nil {
				previewRecord = append(previewRecord, field{"effective", *previewed.Effective})
			}
			if previewed.Renews != nil {
				previewRecord = append(previewRecord, field{"renews", *previewed.Renews})
			}
			return writeRecords(cmd, "plan_preview", []record{previewRecord})
		},
	}
	preview.Flags().StringVar(&previewPlanID, "plan", "", "plan ID from plan list")
	for _, subcommand := range []*cobra.Command{list, change, preview} {
		subcommand.Flags().String(flagKey, "", "account key (or "+args.accountKeyEnvironment()+")")
		addFormatFlag(subcommand, args)
		command.AddCommand(subcommand)
	}
	return command
}
