package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTUIAnalyzeRunnerGeneratesVisualization locks CLI parity for the
// Analyze tab: whenever policies are written to an output directory, the
// flowguarder-visualization.html must be generated alongside them — exactly
// like the CLI, where the visualization is generated whenever --output is
// set and --skip-visualize is absent (writeVisualizationHTML no-ops on an
// empty outDir). Regression guard: tuiAnalyzeRunner used to hardcode
// skipVisualize:true so TUI runs never produced the HTML file.
func TestTUIAnalyzeRunnerGeneratesVisualization(t *testing.T) {
	// No t.Parallel(): the runner mutates the global rootFlags (same
	// convention as TestTUIAnalyzeRunnerCapturesLogLines).
	outDir := t.TempDir()
	_, err := tuiAnalyzeRunner("../../testdata/hubble/protojson.jsonl", outDir, "text", "auto", false, false, false, nil, 10, "auto")
	if err != nil {
		t.Fatalf("runner error: %v", err)
	}

	vizPath := filepath.Join(outDir, "flowguarder-visualization.html")
	assert.FileExists(t, vizPath)

	data, readErr := os.ReadFile(vizPath)
	if readErr != nil {
		t.Fatalf("read visualization: %v", readErr)
	}
	// Tier sanity: tiny fixture graph resolves to the curved layout.
	if !strings.Contains(string(data), `var VIZ_MODE="curved";`) {
		t.Error("visualization missing curved-tier marker var VIZ_MODE=\"curved\"")
	}
}
