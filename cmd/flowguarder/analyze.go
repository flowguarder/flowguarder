package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/flowguarder/flowguarder/cmd/flowguarder/tui"
	"github.com/flowguarder/flowguarder/pkg/simulate"
	"github.com/spf13/cobra"
)

var analyzeTUISimulate bool

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
		if analyzeTUISimulate && rootFlags.outputDir == "" {
			fmt.Fprintln(os.Stderr, "error: --tui-simulate requires --output")
			return fmt.Errorf("--tui-simulate requires --output")
		}

		if err := runAnalyzePipeline(cmd, args[0], &rootFlags); err != nil {
			return err
		}

		if analyzeTUISimulate {
			absDir, err := filepath.Abs(rootFlags.outputDir)
			if err != nil {
				return fmt.Errorf("resolve output path: %w", err)
			}
			policies, _, loadErr := simulate.LoadPolicies(absDir)
			if loadErr != nil {
				return fmt.Errorf("load policies for TUI: %w", loadErr)
			}
			objects := tui.ExtractSelectableObjects(policies)
			return tui.Run(objects, absDir, policies)
		}

		return nil
	},
}

func init() {
	// Local flags for analyze
	analyzeCmd.Flags().Bool("dry-run", false, "only validate input, do not generate output")
	analyzeCmd.Flags().StringSliceVarP(&rootFlags.reports, "report", "r", nil, "report type (repeatable: top-flows, uncovered, coverage, egress-world, drops, anomalies)")
	analyzeCmd.Flags().IntVar(&rootFlags.topN, "top-n", 10, "number of top items to display in reports")
	analyzeCmd.Flags().BoolVar(&rootFlags.generateUncovered, "generate-uncovered", false, "generate policies for uncovered traffic")
	analyzeCmd.Flags().BoolVar(&analyzeTUISimulate, "tui-simulate", false, "after analysis, launch interactive TUI for traffic simulation")
}
