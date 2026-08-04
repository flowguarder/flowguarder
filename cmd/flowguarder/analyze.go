package main

import (
	"github.com/spf13/cobra"
)

// analyzeCmd represents the analyze subcommand.
var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Analyze flow log files or directories",
	Long: `Analyze flow log files or directories to extract network traffic patterns,
detect anomalies, and generate Kubernetes NetworkPolicy manifests.

Examples:
  # Analyze a single Hubble JSON log file
  flowguarder analyze hubble-flows.json

  # Analyze a directory of log files
  flowguarder analyze /var/log/flows/

  # Pipe logs from stdin
  cat hubble-flows.json | flowguarder analyze -

  # Force Calico parser and output JSON
  flowguarder analyze calico-flows.log --source calico --format json

  # Generate CiliumNetworkPolicies with default deny
  flowguarder analyze flows.json --cilium --default-deny

  # Use a custom config and write outputs to a directory
  flowguarder analyze flows.json --config config.yaml --output ./policies`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAnalyzePipeline(cmd, args[0], &rootFlags)
	},
}

func init() {
	// Local flags for analyze
	analyzeCmd.Flags().Bool("dry-run", false, "only validate input, do not generate output")
	analyzeCmd.Flags().StringSliceVarP(&rootFlags.reports, "report", "r", nil, "report type (repeatable: top-flows, uncovered, coverage, egress-world, drops, anomalies)")
	analyzeCmd.Flags().IntVar(&rootFlags.topN, "top-n", 10, "number of top items to display in reports")
	analyzeCmd.Flags().BoolVar(&rootFlags.generateUncovered, "generate-uncovered", false, "generate policies for uncovered traffic")
}
