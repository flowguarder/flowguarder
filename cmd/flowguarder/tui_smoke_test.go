package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// NOTE: no t.Parallel() — rootCmd, analyzeCmd, liveCmd, simulateCmd are
// package-level globals; concurrent Execute() calls would race on shared state.

func TestSimulateTUIFlagExists(t *testing.T) {
	f := simulateCmd.Flags().Lookup("tui")
	if f == nil {
		t.Fatal("--tui flag not registered on simulateCmd")
	}
	if f.DefValue != "false" {
		t.Errorf("--tui default = %q, want false", f.DefValue)
	}
}

func TestAnalyzeTUISimulateFlagExists(t *testing.T) {
	f := analyzeCmd.Flags().Lookup("tui-simulate")
	if f == nil {
		t.Fatal("--tui-simulate flag not registered on analyzeCmd")
	}
	if f.DefValue != "false" {
		t.Errorf("--tui-simulate default = %q, want false", f.DefValue)
	}
}

func TestLiveTUISimulateFlagExists(t *testing.T) {
	f := liveCmd.Flags().Lookup("tui-simulate")
	if f == nil {
		t.Fatal("--tui-simulate flag not registered on liveCmd")
	}
	if f.DefValue != "false" {
		t.Errorf("--tui-simulate default = %q, want false", f.DefValue)
	}
}

func TestSimulateTUIRequiresPolicies(t *testing.T) {
	// --tui without --policies should error
	cmd := &cobra.Command{}
	cmd.AddCommand(simulateCmd)
	cmd.SetArgs([]string{"simulate", "--tui"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --tui used without --policies")
	}
}

func TestAnalyzeTUISimulateRequiresOutput(t *testing.T) {
	// --tui-simulate without --output should error
	cmd := &cobra.Command{}
	cmd.AddCommand(analyzeCmd)
	cmd.SetArgs([]string{"analyze", "nonexistent.jsonl", "--tui-simulate"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --tui-simulate used without --output")
	}
}
