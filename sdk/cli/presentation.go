package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// ResultField preserves the SDK's field ordering for application presentation.
type ResultField struct {
	Name  string
	Value any
}

// Presentation optionally adapts SDK results to the embedding application's CLI.
// Without it, commands retain their text, JSON, and JSONL presentation.
type Presentation struct {
	DefaultFormat string
	FormatUsage   string
	Validate      func(*cobra.Command) error
	Results       func(*cobra.Command, string, [][]ResultField) error
	Progress      func(*cobra.Command, string) error
	Notice        func(*cobra.Command, string, string) error
}

type presentationKey struct{}

func commandPresentation(command *cobra.Command) *Presentation {
	presentation, _ := command.Context().Value(presentationKey{}).(*Presentation)
	return presentation
}

func configurePresentation(command *cobra.Command, args *Args) {
	presentation := args.Presentation
	if presentation != nil {
		copied := *presentation
		presentation = &copied
	}
	format, usage := formatText, "stdout format (text|jsonl|json)"
	if presentation != nil {
		if presentation.DefaultFormat != "" {
			format = presentation.DefaultFormat
		}
		if presentation.FormatUsage != "" {
			usage = presentation.FormatUsage
		}
	}
	command.Flags().String(flagStdoutFormat, format, usage)
	run := command.RunE
	command.RunE = func(command *cobra.Command, positional []string) error {
		if presentation != nil && presentation.Validate != nil {
			if err := presentation.Validate(command); err != nil {
				return err
			}
		} else {
			format, err := command.Flags().GetString(flagStdoutFormat)
			if err != nil {
				return err
			}
			if format != formatText && format != formatJSON && format != formatJSONL {
				return fmt.Errorf("--stdout-format must be text, jsonl or json, not %q", format)
			}
		}
		if presentation != nil {
			command.SetContext(context.WithValue(command.Context(), presentationKey{}, presentation))
		}
		return run(command, positional)
	}
}

func writeProgress(command *cobra.Command, instanceID, step string) error {
	presentation := commandPresentation(command)
	if presentation != nil && presentation.Progress != nil {
		return presentation.Progress(command, "Instance "+instanceID+": "+step)
	}
	_, err := fmt.Fprintln(command.ErrOrStderr(), "event=progress instance="+instanceID+" step="+step)
	return err
}

// writeApproval preserves the legacy prompt unless an application supplies presentation.
func writeApproval(command *cobra.Command, address string) error {
	presentation := commandPresentation(command)
	if presentation != nil && presentation.Notice != nil {
		return presentation.Notice(command, "approval_required", "Approve the sign-in at "+address)
	}
	_, err := fmt.Fprintln(command.ErrOrStderr(), "event=approval approval_url="+address)
	return err
}

func browserNotice(command *cobra.Command, address string) error {
	message := "Open " + address + " in a browser to continue."
	presentation := commandPresentation(command)
	if presentation != nil && presentation.Notice != nil {
		return presentation.Notice(command, "browser_required", message)
	}
	_, err := fmt.Fprintln(command.ErrOrStderr(), message)
	return err
}
