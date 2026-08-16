package main

import "github.com/spf13/cobra"

// Build-time variables injected via goreleaser ldflags.
var (
	version = "1.3.1"

	//nolint:unused // injected via goreleaser ldflags
	commit = "none"
	//nolint:unused // injected via goreleaser ldflags
	buildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the flowguarder version",
	Long:  "Print the flowguarder version.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("%s\n", version)
	},
}
