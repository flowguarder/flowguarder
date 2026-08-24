package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/flowguarder/flowguarder/cmd/flowguarder/tui"
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/simulate"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newTUIRunners() tui.UnifiedOpts {
	return tui.UnifiedOpts{
		AnalyzeRunner: tuiAnalyzeRunner,
		LiveRunner:    tuiLiveRunner,
		PolicyLoader:  tuiPolicyLoader,
	}
}

func tuiAnalyzeRunner(sourcePath, outputDir, format, policyFormat string, strict, defaultDeny, cilium bool, reports []string, topN int, vizLayout string) (string, error) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "analyze", SilenceUsage: true, SilenceErrors: true}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().AddFlagSet(pflag.NewFlagSet("tui", pflag.ContinueOnError))

	cfgPath := ""
	if rootFlags.configPath != "" {
		cfgPath = rootFlags.configPath
	}

	saved := rootFlags
	defer func() { rootFlags = saved }()

	// Route the standard logger into the capture buffer: pkg/policy logs
	// warnings (e.g. "skipping synthetic workload") to the default stderr
	// logger, which would paint raw rows over Bubble Tea's alt-screen and
	// corrupt the frame. Captured lines surface in the Output pane instead.
	prevLogWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLogWriter)

	rootFlags = rootCmdData{
		configPath:        cfgPath,
		source:            saved.source,
		kubeconfig:        saved.kubeconfig,
		outputDir:         outputDir,
		format:            format,
		strict:            strict,
		defaultDeny:       defaultDeny,
		policyFormat:      policyFormat,
		cilium:            cilium,
		reports:           reports,
		topN:              topN,
		generateUncovered: false,
		// CLI parity: generate the visualization whenever policies are
		// written; writeVisualizationHTML no-ops on empty outDir.
		skipVisualize: outputDir == "",
		vizLayout:     vizLayout,
	}

	if err := runAnalyzePipeline(cmd, sourcePath, &rootFlags); err != nil {
		return buf.String(), err
	}

	return buf.String(), nil
}

func tuiLiveRunner(ctx context.Context, source tui.LiveSource, address, outputDir, format, policyFormat string, strict, defaultDeny bool, reports []string, vizLayout string) (string, error) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "live", SilenceUsage: true, SilenceErrors: true}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().AddFlagSet(pflag.NewFlagSet("tui", pflag.ContinueOnError))

	cfgPath := ""
	if rootFlags.configPath != "" {
		cfgPath = rootFlags.configPath
	}

	saved := rootFlags
	defer func() { rootFlags = saved }()

	prevLogWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLogWriter)

	rootFlags = rootCmdData{
		configPath:   cfgPath,
		source:       saved.source,
		kubeconfig:   saved.kubeconfig,
		outputDir:    outputDir,
		format:       format,
		strict:       strict,
		defaultDeny:  defaultDeny,
		policyFormat: policyFormat,
		reports:      reports,
		vizLayout:    vizLayout,
	}

	switch source {
	case tui.LiveSourceHubble:
		if err := runLiveHubble(ctx, cmd, address, parser.SourceHubble, address); err != nil {
			return buf.String(), err
		}
	case tui.LiveSourceCalico:
		absPath, err := filepath.Abs(address)
		if err != nil {
			return "", fmt.Errorf("resolve calico file path: %w", err)
		}
		info, statErr := os.Stat(absPath)
		if statErr != nil {
			return "", fmt.Errorf("calico file not found: %w", statErr)
		}
		if info.IsDir() {
			return "", fmt.Errorf("calico source must be a file, not a directory: %s", absPath)
		}
		if err := runLiveCalico(ctx, cmd, absPath, parser.SourceCalico, address); err != nil {
			return buf.String(), err
		}
	}

	return buf.String(), nil
}

func tuiPolicyLoader(dir string) ([]simulate.LoadedPolicy, tui.SelectableObjects, error) {
	policies, _, err := simulate.LoadPolicies(dir)
	if err != nil {
		return nil, tui.SelectableObjects{}, err
	}
	objects := tui.ExtractSelectableObjects(policies)
	return policies, objects, nil
}
