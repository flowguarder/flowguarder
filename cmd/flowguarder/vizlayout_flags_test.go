package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: no t.Parallel() in this file — rootCmd, rootFlags, and liveCmd are
// package-level globals; concurrent Execute()/runLiveCommand calls would race
// on shared state (same caveat as simulate_test.go / tui_smoke_test.go).

// hubbleFixture is a small Hubble JSONL input that parses quickly and is
// already exercised by TestAnalyzeFlags_Validation.
const hubbleFixture = "../../testdata/hubble/protojson.jsonl"

// runVizRoot invokes the flowguarder root command in-process via Cobra,
// snapshotting rootFlags so flag mutations never leak between tests.
func runVizRoot(t *testing.T, args ...string) (stdout, stderr *bytes.Buffer, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	saved := rootFlags
	savedTUISimulate := analyzeTUISimulate
	// Earlier tests (tui_smoke_test.go) can leave --tui-simulate set; our args
	// never pass it, so force the off state instead of trusting leaked state.
	analyzeTUISimulate = false
	defer func() {
		rootFlags = saved
		analyzeTUISimulate = savedTUISimulate
	}()
	// tui_smoke_test.go re-parents analyzeCmd onto throwaway commands; put it
	// back under rootCmd or inherited persistent flags (--output, --viz-layout)
	// fail to resolve during parsing ("unknown flag").
	if analyzeCmd.Parent() != rootCmd {
		rootCmd.AddCommand(analyzeCmd)
	}
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errBuf)
	err = rootCmd.Execute()
	return &out, &errBuf, err
}

func TestVizLayoutFlagRegistered(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("viz-layout")
	require.NotNil(t, f, "--viz-layout persistent flag not registered on rootCmd")
	assert.Equal(t, "auto", f.DefValue, "--viz-layout default must be auto")

	usage := f.Usage
	for _, tok := range []string{"auto", "straight", "orthogonal", "curved"} {
		assert.Contains(t, usage, tok, "flag help must mention %q", tok)
	}

	// The rendered root usage/help output must surface the flag.
	for _, tok := range []string{"--viz-layout", "auto", "straight", "orthogonal", "curved"} {
		assert.Contains(t, rootCmd.UsageString(), tok, "help output must contain %q", tok)
	}
}

func TestVizLayoutBogusValueFailsBeforeWrite(t *testing.T) {
	outDir := t.TempDir()

	stdout, stderr, err := runVizRoot(t,
		"analyze", hubbleFixture,
		"--output", outDir,
		"--viz-layout=bogus",
	)

	// Execute() returning an error is what makes main exit non-zero.
	require.Error(t, err, "bogus --viz-layout must fail the command")

	// Cobra routes RunE errors to stderr; the message must list ALL four values.
	assert.Contains(t, stderr.String(), "auto|straight|orthogonal|curved")
	assert.NotContains(t, stdout.String(), "Wrote policy files")

	assert.NoFileExists(t, filepath.Join(outDir, "flowguarder-visualization.html"),
		"no visualization HTML may be written for an invalid layout mode")
}

func TestVizLayoutBogusStillValidatedWithSkipVisualize(t *testing.T) {
	outDir := t.TempDir()

	// --skip-visualize suppresses the HTML write entirely, yet an invalid
	// --viz-layout must still fail: entry-time validation, not write-time.
	_, stderr, err := runVizRoot(t,
		"analyze", hubbleFixture,
		"--output", outDir,
		"--skip-visualize",
		"--viz-layout=bogus",
	)

	require.Error(t, err, "validation must fire even with --skip-visualize set")
	assert.Contains(t, stderr.String(), "auto|straight|orthogonal|curved")
	assert.NoFileExists(t, filepath.Join(outDir, "flowguarder-visualization.html"))
}

func TestVizLayoutValidStraightSmoke(t *testing.T) {
	outDir := t.TempDir()

	_, _, err := runVizRoot(t,
		"analyze", hubbleFixture,
		"--output", outDir,
		"--viz-layout=straight",
	)

	require.NoError(t, err, "a valid --viz-layout value must not fail the pipeline")
	assert.FileExists(t, filepath.Join(outDir, "flowguarder-visualization.html"))
}

func TestRunLiveCommandRejectsInvalidVizLayout(t *testing.T) {
	saved := rootFlags
	defer func() { rootFlags = saved }()
	rootFlags.vizLayout = "bogus"

	// runLiveCommand validates at entry, BEFORE the missing-source check,
	// so the layout error wins over "either --hubble-server or --calico-file".
	err := runLiveCommand(&cobra.Command{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "auto|straight|orthogonal|curved")
	assert.NotContains(t, err.Error(), "--hubble-server",
		"layout validation must fire before source resolution")
}

func TestWriteVisualizationHTMLLayoutValidation(t *testing.T) {
	tests := []struct {
		name    string
		layout  string
		wantErr bool
	}{
		{"bogus rejected", "bogus", true},
		{"case variant rejected", "Auto", true},
		{"uppercase rejected", "STRAIGHT", true},
		{"leading whitespace rejected", " auto", true},
		{"empty equals auto", "", false},
		{"auto", "auto", false},
		{"straight", "straight", false},
		{"orthogonal", "orthogonal", false},
		{"curved", "curved", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()

			err := writeVisualizationHTML(outDir, nil, "test-source", false, tc.layout)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "auto|straight|orthogonal|curved")
				assert.NoFileExists(t, filepath.Join(outDir, "flowguarder-visualization.html"))
				return
			}

			require.NoError(t, err)
			assert.FileExists(t, filepath.Join(outDir, "flowguarder-visualization.html"))
		})
	}
}
