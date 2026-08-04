package main

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmdData is the shared flag data for root and subcommands.
var rootFlags rootCmdData

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "flowguarder",
	Short: "Network flow analysis CLI",
	Version: "1.0.0",
	Long: `flowguarder - Network flow analysis CLI

Analyzes Kubernetes network flows from Hubble, Calico, or other CNI log sources,
aggregates them into traffic patterns, detects anomalies, and generates
Kubernetes NetworkPolicy and CiliumNetworkPolicy manifests.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No-op placeholder for future global setup
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&rootFlags.configPath, "config", "", "path to YAML config file")
	rootCmd.PersistentFlags().StringVar(&rootFlags.source, "source", "auto", "flow source type: auto, hubble, calico, goldmane")
	rootCmd.PersistentFlags().StringVar(&rootFlags.outputDir, "output", "", "output directory for policy YAML manifests")
	rootCmd.PersistentFlags().StringVar(&rootFlags.format, "format", "text", "report output format: text, json, both")
	rootCmd.PersistentFlags().BoolVar(&rootFlags.strict, "strict", false, "disable safety margins for policy generation")
	rootCmd.PersistentFlags().BoolVar(&rootFlags.defaultDeny, "default-deny", false, "add deny-all stub policies")
	rootCmd.PersistentFlags().BoolVar(&rootFlags.cilium, "cilium", false, "emit CiliumNetworkPolicy instead of NetworkPolicy")
	rootCmd.PersistentFlags().StringVar(&rootFlags.kubeconfig, "kubeconfig", "", "path to kubeconfig for dry-run diff")

	// Hide the kubeconfig flag from the help text for this subcommand (it's only used by `live`)
	rootCmd.PersistentFlags().MarkHidden("kubeconfig")

	// Register subcommands
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(liveCmd)
	rootCmd.AddCommand(versionCmd)
}
