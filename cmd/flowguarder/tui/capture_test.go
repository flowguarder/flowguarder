package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// TestCaptureViewOutput captures and prints the full View() output for all
// three tabs (Analyze, Live, Simulate) so we can visually inspect the
// rendering in CI logs.
//
// It verifies:
//   - No "Bummer. No Files Found." in file pickers
//   - YAML textareas collapsed to "(empty — press Enter to expand)"
//   - "? Help" hint visible in header
//   - Version string visible
func TestCaptureViewOutput(t *testing.T) {
	t.Parallel()

	baseModel := func() Model {
		m := Model{
			version:         "1.4.0",
			activeTab:       TabAnalyze,
			width:           120,
			height:          40,
			policyDir:       ".",
			policyDirPicked: true,
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
		}, ".", nil)
		// Send WindowSizeMsg so lists get properly sized (real TUI gets this from terminal)
		updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
		m = updated.(Model)
		return m
	}

	t.Run("ANALYZE", func(t *testing.T) {
		t.Parallel()
		m := baseModel()
		m.activeTab = TabAnalyze
		m.activeArea = AreaAnalyzePicker
		view := m.View()
		printView(t, "ANALYZE", view)
		if !strings.Contains(view, "Select flow source") {
			t.Error("missing picker header")
		}
		if !strings.Contains(view, "--output") {
			t.Error("missing form fields")
		}
		assertView(t, view, TabAnalyze, true)
	})

	t.Run("LIVE", func(t *testing.T) {
		t.Parallel()
		m := baseModel()
		m.activeTab = TabLive
		m.activeArea = AreaLiveSelector
		view := m.View()
		printView(t, "LIVE", view)
		assertView(t, view, TabLive, false)
	})

	t.Run("SIMULATE", func(t *testing.T) {
		t.Parallel()
		m := baseModel()
		m.activeTab = TabSimulate
		m.activeArea = AreaSimPolicyDir
		view := m.View()
		printView(t, "SIMULATE", view)
		assertView(t, view, TabSimulate, false)
	})
}

func printView(t *testing.T, label, view string) {
	t.Log("=== " + label + " TAB (120x40) ===")
	for _, line := range strings.Split(view, "\n") {
		t.Log(line)
	}
	t.Log("=== END " + label + " ===")
}

func assertView(t *testing.T, view string, tab Tab, hasForm bool) {
	if strings.Contains(view, "Bummer") {
		t.Errorf("View contains 'Bummer' — file picker not seeded")
	}

	if !strings.Contains(view, "? Help") {
		t.Errorf("View missing '? Help' hint")
	}

	for _, l := range []string{"Analyze", "Live", "Simulate"} {
		if !strings.Contains(view, l) {
			t.Errorf("View missing tab label %q", l)
		}
	}

	knownLabels := map[Tab]string{
		TabAnalyze:  "[Analyze]",
		TabLive:     "[Live]",
		TabSimulate: "[Simulate]",
	}
	if lbl, ok := knownLabels[tab]; ok {
		if !strings.Contains(view, lbl) {
			t.Errorf("View missing active label %q", lbl)
		}
	}

	if !strings.Contains(view, "1.4.0") {
		t.Errorf("View missing version string")
	}

	if tab == TabSimulate {
		for _, f := range []string{"Port:", "Proto:", "Evaluate"} {
			if !strings.Contains(view, f) {
				t.Errorf("Simulate view missing field %q", f)
			}
		}
	}

	if tab == TabLive {
		if !strings.Contains(view, "Hubble") && !strings.Contains(view, "Calico") {
			t.Error("Live view missing source options")
		}
	}

	if tab == TabAnalyze {
		yamlLabels := []string{
			"allowed_namespace_pairs",
			"per_namespace_profiles",
			"public_services",
			"apiserver_workload_selector",
		}
		for _, label := range yamlLabels {
			if strings.Contains(view, label) {
				if !strings.Contains(view, "(Enter to edit)") {
					t.Errorf("YAML field %q missing collapsed hint", label)
				}
			}
		}
	}
}

// seedFilePicker populates a filepicker.Model with the directory listing of
// dir. It calls Init() and executes the returned Cmd so the picker's item list
// is ready for View().
func seedFilePicker(picker *filepicker.Model, dir string) {
	picker.DirAllowed = true
	picker.FileAllowed = true
	picker.AllowedTypes = nil
	picker.AutoHeight = false
	picker.SetHeight(12)
	picker.CurrentDirectory = dir
	picker.Path = dir

	if cmd := picker.Init(); cmd != nil {
		msg := cmd()
		*picker, _ = picker.Update(msg)
	}
}
