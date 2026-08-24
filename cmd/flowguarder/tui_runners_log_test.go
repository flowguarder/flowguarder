package main

import (
	"strings"
	"testing"
)

// TestTUIAnalyzeRunnerCapturesLogLines locks the frame-corruption fix:
// pkg/policy logs warnings through the standard logger (default stderr).
// Inside the TUI those raw stderr rows would paint over Bubble Tea's
// alt-screen and double/ghost the Output and Run lines. The runner must
// route them into the captured output shown in the Output pane instead.
func TestTUIAnalyzeRunnerCapturesLogLines(t *testing.T) {
	out, err := tuiAnalyzeRunner("../../flowlab/hubble-flows-before.jsonl", "", "text", "auto", false, false, false, []string{"top-flows"}, 10, "auto")
	if err != nil {
		t.Fatalf("runner error: %v", err)
	}
	if !strings.Contains(out, "Flows parsed:") {
		t.Error("captured output missing analysis report header")
	}
	if !strings.Contains(out, "skipping synthetic workload") {
		t.Error("log warnings were not captured into output (would leak to stderr and corrupt the TUI frame)")
	}
}
