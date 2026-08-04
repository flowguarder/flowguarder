package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/spf13/cobra"
)

// liveCmd represents the live subcommand.
var liveCmd = &cobra.Command{
	Use:   "live",
	Short: "Stream live flows from Hubble or Calico",
	Long: `Stream live network flows and run the same analysis pipeline as 'analyze'.

Sources:
  --hubble-server   Connect to a Hubble Relay gRPC server (address:port)
  --calico-file     Tail a Calico flow log file for new records

Either --hubble-server or --calico-file must be provided.
The default flags (--config, --source, --output, --format, --strict, --default-deny,
--cilium, --kubeconfig) apply to live mode as well.

Examples:
  # Stream from Hubble Relay
  flowguarder live --hubble-server 127.0.0.1:4245

  # Tail a Calico flow log
  flowguarder live --calico-file /var/log/calico/flows.json

  # Live analysis with Cilium policies and JSON output
  flowguarder live --hubble-server hubble.hubble.svc:443 --cilium --format both`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate that at least one source is specified
		if rootFlags.outputDir == "" {
			// Set a default output if none specified
			rootFlags.outputDir = "policies"
		}
		return runLiveCommand(cmd)
	},
}

func init() {
	// Local flags for live
	liveCmd.Flags().String("hubble-server", "", "Hubble Relay gRPC server address (host:port)")
	liveCmd.Flags().String("calico-file", "", "Calico flow log file to tail")

	// Unhide kubeconfig for live (it's used for dry-run with kubeconfig)
	liveCmd.Flags().String("kubeconfig", "", "path to kubeconfig for dry-run diff")
	_ = liveCmd.Flags().MarkHidden("kubeconfig")
}

// runLiveCommand connects to a live flows source and runs the analysis pipeline.
func runLiveCommand(cmd *cobra.Command) error {
	// Parse the --hubble-server flag from live cmd
	hubbleServer := ""
	if f := cmd.Flags().Lookup("hubble-server"); f != nil {
		hubbleServer = f.Value.String()
	}
	calicoFile := ""
	if f := cmd.Flags().Lookup("calico-file"); f != nil {
		calicoFile = f.Value.String()
	}

	if hubbleServer == "" && calicoFile == "" {
		return fmt.Errorf("either --hubble-server or --calico-file must be provided")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if hubbleServer != "" {
		return runLiveHubble(ctx, cmd, hubbleServer)
	}

	return runLiveCalico(ctx, cmd, calicoFile)
}

// runLiveHubble connects to Hubble Relay via gRPC and runs the analysis pipeline.
func runLiveHubble(ctx context.Context, cmd *cobra.Command, address string) error {
	src := &ingest.HubbleGRPCClient{
		Address: address,
		TLS:     false,
	}

	reader, err := src.Open(ctx)
	if err != nil {
		return fmt.Errorf("opening Hubble Relay: %w", err)
	}
	defer reader.Close()

	// Run the same pipeline as analyze
	return runPipelineFromReader(ctx, cmd, reader)
}

// runLiveCalico tails a Calico flow log file and runs the analysis pipeline.
func runLiveCalico(ctx context.Context, cmd *cobra.Command, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening Calico log file %s: %w", filePath, err)
	}
	defer file.Close()

	// Seek to the end of the file
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	// Fast forward to end
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading to end of %s: %w", filePath, err)
	}

	// Now tail the file with a goroutine that feeds new lines
	lines := make(chan string, 128)
	go func() {
		tailer := bufio.NewReader(file)
		for {
			line, err := tailer.ReadString('\n')
			if err != nil && err != io.EOF {
				cmd.Printf("Error reading tail: %v\n", err)
				return
			}
			// On EOF, wait for more data
			if len(line) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err == io.EOF {
				// Brief sleep before retry
				select {
				case <-time.After(500 * time.Millisecond):
					continue
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Parse and run pipeline on each line
	return runPipelineFromLines(ctx, cmd, lines)
}

// runPipelineFromReader reads flows from a reader and executes the full analysis.
func runPipelineFromReader(ctx context.Context, cmd *cobra.Command, reader io.Reader) error {
	flows := make(chan flow.Flow, 128)
	go func() {
		defer close(flows)
		// Select parser for hubble (which is what grpc source uses)
		p, err := parser.SelectParser(parser.SourceHubble, parser.SourceHubble)
		if err != nil {
			cmd.Printf("Parser error: %v\n", err)
			return
		}
		if err := p.Parse(reader, func(f flow.Flow) error {
			select {
			case flows <- f:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}); err != nil {
			cmd.Printf("Parse error: %v\n", err)
		}
	}()

	return runPipelineFromFlows(ctx, cmd, flows)
}

// runPipelineFromLines tails a file line by line and runs the analysis.
func runPipelineFromLines(ctx context.Context, cmd *cobra.Command, lines <-chan string) error {
	flows := make(chan flow.Flow, 128)
	go func() {
		defer close(flows)
		p, err := parser.SelectParser(parser.SourceCalico, parser.SourceCalico)
		if err != nil {
			cmd.Printf("Parser error: %v\n", err)
			return
		}
		lineReader := &lineReader{ch: lines}
		if err := p.Parse(lineReader, func(f flow.Flow) error {
			select {
			case flows <- f:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}); err != nil {
			cmd.Printf("Parse error: %v\n", err)
		}
	}()

	return runPipelineFromFlows(ctx, cmd, flows)
}

// runPipelineFromFlows runs the analysis pipeline on flowing flows.
func runPipelineFromFlows(ctx context.Context, cmd *cobra.Command, flows <-chan flow.Flow) error {
	var parsedFlows []flow.Flow

loop:
	for {
		select {
		case f, ok := <-flows:
			if !ok {
				break loop
			}
			parsedFlows = append(parsedFlows, f)
		case <-ctx.Done():
			break loop
		}
	}

	if len(parsedFlows) == 0 {
		fmt.Fprintln(os.Stderr, "flowguarder live: no valid flows received")
		return nil
	}

	return runLiveAfterParse(cmd, parsedFlows)
}

// runLiveAfterParse runs the analysis pipeline on already-parsed flows.
func runLiveAfterParse(cmd *cobra.Command, flows []flow.Flow) error {
	cfg, err := config.Load(rootFlags.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	flows = analyze.Classify(flows, cfg)
	workloads := analyze.Aggregate(flows)
	patterns := analyze.ComputePatterns(flows, workloads)
	anomalies := anomaly.RunAll(flows, patterns, workloads, cfg)

	pols := policy.Build(flows, patterns, workloads, anomalies, policy.BuildOptions{
		Cilium:      rootFlags.cilium,
		DefaultDeny: rootFlags.defaultDeny,
		Strict:      rootFlags.strict,
		Config:      &cfg,
	})

	// Write output if directory specified
	if rootFlags.outputDir != "" {
		if err := os.MkdirAll(rootFlags.outputDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
		for _, p := range pols {
			writePolicyYAML(rootFlags.outputDir, p, cfg)
		}
		cmd.Printf("Wrote policy files to %s\n", rootFlags.outputDir)
	}

	// Print report
	if rootFlags.format == "json" || rootFlags.format == "both" {
		printJSONReport(flows, patterns, workloads, anomalies, pols)
	}
	if rootFlags.format == "text" || rootFlags.format == "both" {
		printTextReport(cmd, flows, patterns, workloads, anomalies, pols, nil, 0)
	}

	return nil
}

// lineReader reads strings from a channel with line-by-line semantics.
type lineReader struct {
	ch   <-chan string
	buf  string
	done bool
}

func (lr *lineReader) Read(p []byte) (int, error) {
	if lr.buf == "" || lr.done {
		return 0, io.EOF
	}
	n := copy(p, lr.buf)
	lr.buf = lr.buf[n:]
	return n, nil
}
