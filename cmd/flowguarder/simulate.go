package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/flowguarder/flowguarder/cmd/flowguarder/tui"
	"github.com/flowguarder/flowguarder/pkg/simulate"
	"github.com/spf13/cobra"
)

var simFlags struct {
	policies  string
	src       string
	dst       string
	srcNS     string
	dstNS     string
	srcLabels string
	dstLabels string
	srcIP     string
	dstIP     string
	srcEntity string
	dstEntity string
	port      int
	protocol  string
	direction string
	l7Name    string
	l7Pattern string
	useTUI    bool
}

// ---------------------------------------------------------------------------
// simulateCmd — Cobra command
// ---------------------------------------------------------------------------

var simulateCmd = &cobra.Command{
	Use:   "simulate [flags]",
	Short: "Simulate traffic against policy manifests",
	Long: `Simulate traffic between two endpoints against a directory of
NetworkPolicy and CiliumNetworkPolicy YAML manifests and print the
effective allow/deny verdicts.

Examples:
  # Simulate TCP/8080 between two workloads (namespace/name shorthand)
  flowguarder simulate --policies ./policies --src default/frontend --dst default/backend --port 8080

  # Simulate with explicit labels and namespace
  flowguarder simulate --policies ./policies --src-labels app=web --src-ns production --dst-labels app=api --port 443 --protocol TCP

  # Simulate with literal IPs and JSON output
  flowguarder simulate --policies ./policies --src-ip 10.0.0.5 --dst-ip 10.0.1.5 --port 80 --format json

  # Simulate with Cilium entities (L7 DNS matching)
  flowguarder simulate --policies ./policies --src-entity world --dst-entity cluster --port 53 --protocol UDP --l7-name example.com --l7-pattern "*.example.com"`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// 1. Validate --policies
		if simFlags.policies == "" {
			return fmt.Errorf("simulate: --policies is required")
		}
		// 1b. Resolve and load policies early (needed for TUI mode too)
		absDir, derr := filepath.Abs(simFlags.policies)
		if derr != nil {
			return fmt.Errorf("simulate: resolve policies path: %w", derr)
		}
		policies, loadErrs, err := simulate.LoadPolicies(absDir)
		if err != nil {
			return fmt.Errorf("simulate: load policies: %w", err)
		}
		for _, le := range loadErrs {
			fmt.Fprintf(os.Stderr, "simulate: %s: %s\n", le.File, le.Message)
		}
		// 1c. TUI mode — launch UI, skip all CLI validation
		if simFlags.useTUI {
			if simFlags.src != "" || simFlags.dst != "" || simFlags.port != 0 {
				fmt.Fprintf(os.Stderr, "warning: --tui ignores --src, --dst, --port flags; use the TUI to select endpoints\n")
			}
			objects := tui.ExtractSelectableObjects(policies)
			return tui.Run(objects, absDir, policies)
		}
		// 2. Validate direction
		outDir, err := validateDirection(simFlags.direction)
		if err != nil {
			return err
		}
		// 3. Validate protocol (empty → TCP; unknown → error)
		simFlags.protocol = strings.ToUpper(strings.TrimSpace(simFlags.protocol))
		if simFlags.protocol == "" {
			simFlags.protocol = "TCP"
		}
		switch simFlags.protocol {
		case "TCP", "UDP", "SCTP":
		default:
			return fmt.Errorf("simulate: --protocol must be one of TCP, UDP, SCTP (got %q)", simFlags.protocol)
		}
		// 4. Build endpoints
		src, err := buildEndpoint(simFlags.src, simFlags.srcNS,
			simFlags.srcLabels, simFlags.srcIP, simFlags.srcEntity, "source")
		if err != nil {
			return err
		}
		dst, err := buildEndpoint(simFlags.dst, simFlags.dstNS,
			simFlags.dstLabels, simFlags.dstIP, simFlags.dstEntity, "destination")
		if err != nil {
			return err
		}
		// 5. Build traffic descriptor
		traffic := simulate.Traffic{
			Port:     simFlags.port,
			Protocol: strings.ToUpper(simFlags.protocol),
		}
		if simFlags.l7Name != "" {
			traffic.L7Name = simFlags.l7Name
		}
		if simFlags.l7Pattern != "" {
			traffic.L7Pattern = simFlags.l7Pattern
		}
		l7Traffic := newL7Traffic()
		// 6. Evaluate
		npResult := simulate.EvaluateNetworkPolicy(src, dst, traffic, policies)
		cnpResult := simulate.EvaluateCiliumNetworkPolicy(src, dst, traffic, policies, l7Traffic)
		combined := combineVerdicts(npResult, cnpResult)
		// 7. Output
		format := rootFlags.format
		switch format {
		case "json":
			return printJSON(cmd, src, dst, traffic, combined, outDir)
		case "both":
			printText(cmd, combined, outDir)
			cmd.Println()
			return printJSON(cmd, src, dst, traffic, combined, outDir)
		default:
			printText(cmd, combined, outDir)
			return nil
		}
	},
}

// ---------------------------------------------------------------------------
// Flag registration
// ---------------------------------------------------------------------------

func init() {
	// The persistent --viz-layout flag does not apply to simulate; it only
	// affects the HTML visualization written by analyze/live.
	simulateCmd.Flags().StringVar(&simFlags.policies, "policies", "",
		"directory of NetworkPolicy and CiliumNetworkPolicy YAML files")
	simulateCmd.Flags().StringVar(&simFlags.src, "src", "",
		"source endpoint as namespace/name (e.g. default/frontend)")
	simulateCmd.Flags().StringVar(&simFlags.dst, "dst", "",
		"destination endpoint as namespace/name (e.g. default/backend)")
	simulateCmd.Flags().StringVar(&simFlags.srcNS, "src-ns", "",
		"source namespace (used with --src-labels; default: default)")
	simulateCmd.Flags().StringVar(&simFlags.dstNS, "dst-ns", "",
		"destination namespace (used with --dst-labels; default: default)")
	simulateCmd.Flags().StringVar(&simFlags.srcLabels, "src-labels", "",
		"source labels as comma-separated k=v pairs (e.g. app=web,team=a)")
	simulateCmd.Flags().StringVar(&simFlags.dstLabels, "dst-labels", "",
		"destination labels as comma-separated k=v pairs")
	simulateCmd.Flags().StringVar(&simFlags.srcIP, "src-ip", "",
		"source literal IP or CIDR")
	simulateCmd.Flags().StringVar(&simFlags.dstIP, "dst-ip", "",
		"destination literal IP or CIDR")
	simulateCmd.Flags().StringVar(&simFlags.srcEntity, "src-entity", "",
		"source Cilium entity: world, cluster, host, remote-node, kube-apiserver")
	simulateCmd.Flags().StringVar(&simFlags.dstEntity, "dst-entity", "",
		"destination Cilium entity: world, cluster, host, remote-node, kube-apiserver")
	simulateCmd.Flags().IntVar(&simFlags.port, "port", 0,
		"L4 port (0 = any)")
	simulateCmd.Flags().StringVar(&simFlags.protocol, "protocol", "TCP",
		"L4 protocol: TCP, UDP, SCTP (case-insensitive, normalised uppercase)")
	simulateCmd.Flags().StringVar(&simFlags.direction, "direction", "both",
		"direction to report: ingress, egress, both")
	simulateCmd.Flags().StringVar(&simFlags.l7Name, "l7-name", "",
		"DNS name for L7 CiliumNetworkPolicy matching")
	simulateCmd.Flags().StringVar(&simFlags.l7Pattern, "l7-pattern", "",
		"DNS wildcard pattern for L7 CiliumNetworkPolicy matching")
	simulateCmd.Flags().BoolVar(&simFlags.useTUI, "tui", false,
		"launch interactive terminal UI for simulation")
}

// ---------------------------------------------------------------------------
// Output helpers — delegated to output.go
// ---------------------------------------------------------------------------

// newL7Traffic returns non-nil when L7 flags were set.
func newL7Traffic() *simulate.Traffic {
	if simFlags.l7Name == "" && simFlags.l7Pattern == "" {
		return nil
	}
	return &simulate.Traffic{
		L7Name:    simFlags.l7Name,
		L7Pattern: simFlags.l7Pattern,
	}
}
