package main

import "github.com/spf13/cobra"

// Build-time variables set via -ldflags.
var (
	version   = "1.0.0"
	commit    = "none"
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
