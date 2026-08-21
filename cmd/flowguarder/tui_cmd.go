package main

import (
	"github.com/flowguarder/flowguarder/cmd/flowguarder/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive TUI for analyze, live, and simulate",
	Long: `Launch a full-screen terminal UI with three tabs:

  Analyze  — pick a flow source file/directory, configure options, run analysis
  Live     — configure a Hubble or Calico source and stream live flows
  Simulate — pick policies, source/destination, and evaluate traffic interactively

Navigate with Tab/Shift+Tab between areas, arrow keys within areas,
1/2/3 or ←/→ to switch tabs, ? for help, q to quit.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.RunUnified(version, rootFlags.configPath, newTUIRunners())
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
