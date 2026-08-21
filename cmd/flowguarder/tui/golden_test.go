package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// TestGoldenUISnapshots captures golden file snapshots of the TUI for all tabs
// and focus states. Run with UPDATE_GOLDEN=1 to regenerate golden files.
//
// States whose view renders a seeded file picker are validated with Contains
// assertions only (containsOnly): the picker embeds os.Stat sizes, and a
// directory's stat size is filesystem-specific (APFS 96B vs ext4 4.1kB), so
// byte-exact snapshots of those views are not portable across machines.
func TestGoldenUISnapshots(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	goldenDir := "testdata/golden"

	testCases := []struct {
		name          string
		setupModel    func() Model
		expectedLines []string // must-contain lines for basic validation
		containsOnly  bool     // skip byte-exact golden diff; see doc comment
	}{
		{
			name: "analyze-tab-picker-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabAnalyze
				m.activeArea = AreaAnalyzePicker
				m.analyzeTab.pickerFocused = true
				return m
			},
			expectedLines: []string{"Select flow source", "Source:", "Options:", "Reports:"},
			containsOnly:  true,
		},
		{
			name: "analyze-tab-form-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabAnalyze
				m.activeArea = AreaAnalyzeForm
				m.analyzeTab.pickerFocused = false
				return m
			},
			expectedLines: []string{"Select flow source", "Source:", "Options:", "Reports:"},
			containsOnly:  true,
		},
		{
			name: "analyze-tab-reports-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabAnalyze
				m.activeArea = AreaAnalyzeReports
				m.analyzeTab.pickerFocused = false
				m.analyzeReports = m.analyzeReports.Focus().(AnalyzeReports)
				return m
			},
			expectedLines: []string{"Select flow source", "Reports:", "top-flows"},
			containsOnly:  true,
		},
		{
			name: "analyze-tab-run-button-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabAnalyze
				m.activeArea = AreaAnalyzeRun
				return m
			},
			expectedLines: []string{"Select flow source", "▶"},
			containsOnly:  true,
		},
		{
			name: "live-tab-selector-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabLive
				m.activeArea = AreaLiveSelector
				m.liveTab.focusIndex = 0
				return m
			},
			expectedLines: []string{"Select flow source", "Hubble", "Calico", "Options:"},
		},
		{
			name: "live-tab-form-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabLive
				m.activeArea = AreaLiveForm
				m.liveTab.focusIndex = 1
				return m
			},
			expectedLines: []string{"Select flow source", "Hubble", "Calico", "Options:"},
		},
		{
			name: "live-tab-run-button-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabLive
				m.activeArea = AreaLiveButton
				m.liveTab.focusIndex = 2
				return m
			},
			expectedLines: []string{"Select flow source", "Run ▶"},
		},
		{
			name: "simulate-tab-policy-dir",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimPolicyDir
				return m
			},
			expectedLines: []string{"Select policy directory", "Policy dir:"},
			containsOnly:  true,
		},
		{
			name: "simulate-tab-src-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimSrc
				m.policyDirPicked = true
				m.policyDir = "."
				m.srcListInit = true
				return m
			},
			expectedLines: []string{"Source Pickers", "Destination Pickers", "Port:", "Proto:", "Evaluate"},
		},
		{
			name: "simulate-tab-dst-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimDst
				m.policyDirPicked = true
				m.policyDir = "."
				m.srcListInit = true
				m.dstListInit = true
				return m
			},
			expectedLines: []string{"Source Pickers", "Destination Pickers", "Port:", "Proto:", "Evaluate"},
		},
		{
			name: "simulate-tab-inputs-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimInputs
				m.policyDirPicked = true
				m.policyDir = "."
				m.srcListInit = true
				m.dstListInit = true
				return m
			},
			expectedLines: []string{"Source Pickers", "Destination Pickers", "Port:", "Proto:", "Evaluate"},
		},
		{
			name: "simulate-tab-evaluate-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimEval
				m.policyDirPicked = true
				m.policyDir = "."
				m.srcListInit = true
				m.dstListInit = true
				return m
			},
			expectedLines: []string{"Source Pickers", "Destination Pickers", "Port:", "Proto:", "Evaluate"},
		},
		{
			name: "simulate-tab-result-focused",
			setupModel: func() Model {
				m := baseGoldenModel()
				m.activeTab = TabSimulate
				m.activeArea = AreaSimInputs // Result is shown in inputs area
				m.policyDirPicked = true
				m.policyDir = "."
				m.srcListInit = true
				m.dstListInit = true
				return m
			},
			expectedLines: []string{"Source Pickers", "Destination Pickers", "Port:", "Proto:", "Evaluate", "Select source, destination"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := tc.setupModel()
			// Send WindowSizeMsg so lists get properly sized
			updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
			m = updated.(Model)

			view := m.View()

			// Basic validation - ensure expected content is present
			for _, line := range tc.expectedLines {
				if !strings.Contains(view, line) {
					t.Errorf("golden snapshot %q missing expected content %q", tc.name, line)
				}
			}

			// Golden file comparison
			goldenPath := filepath.Join(goldenDir, tc.name+".txt")
			if tc.containsOnly {
				return
			}
			if update {
				if err := os.MkdirAll(goldenDir, 0755); err != nil {
					t.Fatalf("failed to create golden dir: %v", err)
				}
				if err := os.WriteFile(goldenPath, []byte(view), 0644); err != nil {
					t.Fatalf("failed to write golden file: %v", err)
				}
				t.Logf("Updated golden file: %s", goldenPath)
			} else {
				golden, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("golden file not found (run with UPDATE_GOLDEN=1): %v", err)
				}
				if string(golden) != view {
					t.Errorf("golden snapshot mismatch for %s\nRun with UPDATE_GOLDEN=1 to update", tc.name)
					// Show diff for debugging
					t.Logf("Expected (%d chars):\n%s", len(golden), string(golden))
					t.Logf("Got (%d chars):\n%s", len(view), view)
				}
			}
		})
	}
}

// baseGoldenModel creates a base model configured for golden file testing.
func baseGoldenModel() Model {
	m := Model{
		version:         "1.4.0",
		activeTab:       TabAnalyze,
		width:           120,
		height:          40,
		policyDir:       "", // empty so policyDirPicked stays false
		policyDirPicked: false,
	}
	m.outputViewport = viewport.New(120, 5)
	m.analyzeTab = NewAnalyzeTab()
	seedFilePicker(&m.analyzeTab.picker, ".")
	seedFilePicker(&m.policyDirPicker, ".")
	m.analyzeReports = NewAnalyzeReports("Reports", "Select report sections")
	m.analyzeTab.form = blurForm(m.analyzeTab.form)
	m.analyzeTab.pickerFocused = true
	m.initInputs()
	m.liveTab = NewLiveTab()
	m.InitModel(SelectableObjects{
		Workloads: []SelectableWorkload{
			{Namespace: "default", Name: "frontend", Labels: map[string]string{"app": "frontend"}},
			{Namespace: "default", Name: "backend", Labels: map[string]string{"app": "backend"}},
		},
		Entities: []string{"world", "cluster", "host", "remote-node", "kube-apiserver"},
		CIDRs:    []SelectableCIDR{{CIDR: "10.96.0.0/12", Desc: "service CIDR"}},
	}, "", nil)
	return m
}
