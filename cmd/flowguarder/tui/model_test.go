package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

func TestInitReturnsNil(t *testing.T) {
	m := Model{}
	cmd := m.Init()
	if cmd != nil {
		t.Errorf("Init() = %T, want nil", cmd)
	}
}

func TestUpdateWindowSize(t *testing.T) {
	m := Model{}
	model, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	updated, ok := model.(Model)
	if !ok {
		t.Fatal("Update did not return a Model")
	}
	if updated.width != 80 {
		t.Errorf("width = %d, want 80", updated.width)
	}
	if updated.height != 24 {
		t.Errorf("height = %d, want 24", updated.height)
	}
}

func TestUpdateCtrlCQuits(t *testing.T) {
	m := Model{}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	updated, ok := model.(Model)
	if !ok {
		t.Fatal("Update did not return a Model")
	}
	if !updated.quitting {
		t.Error("Model didn't set quitting after ctrl+c")
	}
	if cmd == nil {
		t.Fatal("Expected non-nil command after ctrl+c")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("Expected tea.Quit command after ctrl+c")
	}
}

func TestUpdateQKeyQuits(t *testing.T) {
	m := Model{}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	updated, ok := model.(Model)
	if !ok {
		t.Fatal("Update did not return a Model")
	}
	if !updated.quitting {
		t.Error("Model didn't set quitting after q key")
	}
	if cmd == nil {
		t.Fatal("Expected non-nil command after q key")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("Expected tea.Quit command after q key")
	}
}

func TestViewNotQuitting(t *testing.T) {
	m := Model{}
	view := m.View()
	if view == "" {
		t.Error("View() returned empty string when not quitting")
	}
}

func TestViewQuitting(t *testing.T) {
	m := Model{quitting: true}
	got := m.View()
	want := "Goodbye!\n"
	if got != want {
		t.Errorf("View() = %q, want %q", got, want)
	}
}

func TestUpdateIgnoresOtherKeys(t *testing.T) {
	m := Model{width: 80, height: 24, quitting: true}
	// Changing from quitting should not be possible via Update —
	// once quitting, key messages don't toggle back.
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	updated, ok := model.(Model)
	if !ok {
		t.Fatal("Update did not return a Model")
	}
	if !updated.quitting {
		t.Error("Model quitting was reset by unrelated key")
	}
}

func TestTabNavigation(t *testing.T) {
	// Number keys 1/2/3 switch tabs from any state.
	numberCases := []struct {
		key  rune
		want Tab
	}{
		{'1', TabAnalyze},
		{'2', TabLive},
		{'3', TabSimulate},
	}
	for _, c := range numberCases {
		m := Model{}
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{c.key}})
		updated, ok := model.(Model)
		if !ok {
			t.Fatalf("Update did not return a Model for key %q", string(c.key))
		}
		if updated.activeTab != c.want {
			t.Errorf("key %q: activeTab = %v, want %v", string(c.key), updated.activeTab, c.want)
		}
	}

	// Left/right arrows cycle tabs at the top level.
	m := Model{activeTab: TabAnalyze}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated, ok := model.(Model)
	if !ok {
		t.Fatal("Update did not return a Model")
	}
	if updated.activeTab != TabLive {
		t.Errorf("Right from Analyze = %v, want TabLive", updated.activeTab)
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated, _ = model.(Model)
	if updated.activeTab != TabSimulate {
		t.Errorf("Right from Live = %v, want TabSimulate", updated.activeTab)
	}

	// Left cycles back (from Live).
	mLive := Model{activeTab: TabLive}
	modelLive, _ := mLive.Update(tea.KeyMsg{Type: tea.KeyLeft})
	updatedLive, _ := modelLive.(Model)
	if updatedLive.activeTab != TabAnalyze {
		t.Errorf("Left from Live = %v, want TabAnalyze", updatedLive.activeTab)
	}

	// On the Simulate tab, Tab/Shift+Tab cycle areas within the tab.
	mSim := Model{activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true, activeArea: AreaSimSrc}
	modelSim, _ := mSim.Update(tea.KeyMsg{Type: tea.KeyTab})
	updatedSim, _ := modelSim.(Model)
	if updatedSim.activeTab != TabSimulate {
		t.Errorf("Tab on Simulate changed tab = %v, want TabSimulate", updatedSim.activeTab)
	}
	if updatedSim.activeArea != AreaSimDst {
		t.Errorf("Tab on Simulate area = %v, want AreaSimDst", updatedSim.activeArea)
	}
}

func TestViewHeaderContainsTabs(t *testing.T) {
	m := Model{activeTab: TabAnalyze}
	view := m.View()
	for _, label := range []string{"Analyze", "Live", "Simulate"} {
		if !strings.Contains(view, label) {
			t.Errorf("View() missing tab label %q\nGot:\n%s", label, view)
		}
	}
}

func TestViewHeaderContainsVersion(t *testing.T) {
	m := Model{version: "1.4.0"}
	view := m.View()
	if !strings.Contains(view, "1.4.0") {
		t.Errorf("View() missing version 1.4.0\nGot:\n%s", view)
	}
}

// ---------------------------------------------------------------------------
// Tab switching: Tab/Shift+Tab cycles between non-Simulate tabs
// ---------------------------------------------------------------------------

func TestTabCyclingFullRoundTrip(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, policyDirPicked: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated := model.(Model)
	if updated.activeTab != TabLive {
		t.Errorf("Right from Analyze: got %v, want TabLive", updated.activeTab)
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated = model.(Model)
	if updated.activeTab != TabSimulate {
		t.Errorf("Right from Live: got %v, want TabSimulate", updated.activeTab)
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated = model.(Model)
	if updated.activeTab != TabAnalyze {
		t.Errorf("Right from Simulate wraps: got %v, want TabAnalyze", updated.activeTab)
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyLeft})
	updated = model.(Model)
	if updated.activeTab != TabSimulate {
		t.Errorf("Left from Analyze wraps: got %v, want TabSimulate", updated.activeTab)
	}

	updated.activeTab = TabLive
	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyLeft})
	updated = model.(Model)
	if updated.activeTab != TabAnalyze {
		t.Errorf("Left from Live: got %v, want TabAnalyze", updated.activeTab)
	}
}

func TestTabShiftTabFromReportsReturnsToForm(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, activeArea: AreaAnalyzeReports}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	updated := model.(Model)

	if updated.activeArea != AreaAnalyzeForm {
		t.Errorf("activeArea = %v, want AreaAnalyzeForm", updated.activeArea)
	}
	if updated.activeTab != TabAnalyze {
		t.Errorf("activeTab = %v, want TabAnalyze", updated.activeTab)
	}
}

func TestTabFromAnalyzePickerGoesToNextTab(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, activeArea: AreaAnalyzePicker}
	m.analyzeTab = NewAnalyzeTab()

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated := model.(Model)

	if updated.activeArea != AreaAnalyzeForm {
		t.Errorf("Tab from picker: area = %v, want AreaAnalyzeForm", updated.activeArea)
	}
}

func TestTabFromAnalyzeFormToReports(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, activeArea: AreaAnalyzeForm}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeTab.pickerFocused = false
	m.analyzeTab.form = m.analyzeTab.form.SetFocus(0)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated := model.(Model)

	if updated.activeTab != TabAnalyze {
		t.Errorf("activeTab = %v, want TabAnalyze (should stay)", updated.activeTab)
	}
	if updated.activeArea != AreaAnalyzeReports {
		t.Errorf("activeArea = %v, want AreaAnalyzeReports", updated.activeArea)
	}
}

// ---------------------------------------------------------------------------
// Analyze tab: picker/form/reports transitions
// ---------------------------------------------------------------------------

func TestAnalyzeFormEscReturnsToPicker(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeTab.pickerFocused = false
	m.analyzeTab.form = m.analyzeTab.form.SetFocus(0)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated := model.(Model)

	if !updated.analyzeTab.pickerFocused {
		t.Error("esc should return to picker")
	}
}

func TestAnalyzeReportsEscReturnsToForm(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeTab.pickerFocused = false
	m.analyzeReports = NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated := model.(Model)

	if updated.analyzeReports.Focused() {
		t.Error("reports should be blurred after esc")
	}
}

func TestAnalyzeFormValuesRoundTrip(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeTab.pickerFocused = false

	outField := m.analyzeTab.form.fields[0].(TextField).Focus().(TextField)
	updatedField, _ := outField.Update(keyMsg("/tmp/out"))
	m.analyzeTab.form.fields[0] = updatedField.(TextField)

	values := m.analyzeTab.Values()
	if values["--output"] != "/tmp/out" {
		t.Errorf("--output = %q, want /tmp/out", values["--output"])
	}
}

// ---------------------------------------------------------------------------
// Analyze reports: toggle report types + Run button
// ---------------------------------------------------------------------------

func TestAnalyzeReportsToggleWithSpace(t *testing.T) {
	t.Parallel()

	reports := NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)
	reports.cursor = 0

	updated, _ := reports.Update(tea.KeyMsg{Type: tea.KeySpace})
	r := updated.(AnalyzeReports)

	// Cursor 0 in sorted order = "anomalies" (alphabetically first).
	toggled := r.sortedOptions()[0]
	if !r.selected[toggled] {
		t.Errorf("space should toggle report %q", toggled)
	}

	updated, _ = r.Update(tea.KeyMsg{Type: tea.KeySpace})
	r = updated.(AnalyzeReports)
	if r.selected[toggled] {
		t.Errorf("space should toggle report off %q", toggled)
	}
}

func TestAnalyzeReportsToggleWithEnter(t *testing.T) {
	t.Parallel()

	reports := NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)
	reports.cursor = 1

	updated, _ := reports.Update(tea.KeyMsg{Type: tea.KeyEnter})
	r := updated.(AnalyzeReports)

	// Cursor 1 in sorted order = "coverage" (alphabetically 2nd).
	toggled := r.sortedOptions()[1]
	if !r.selected[toggled] {
		t.Errorf("enter should toggle report %q", toggled)
	}
}

func TestAnalyzeReportsValuesSorted(t *testing.T) {
	t.Parallel()

	r := NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)
	r.cursor = 0
	updated, _ := r.Update(tea.KeyMsg{Type: tea.KeySpace})
	r = updated.(AnalyzeReports)

	r.cursor = 2
	updated, _ = r.Update(tea.KeyMsg{Type: tea.KeySpace})
	r = updated.(AnalyzeReports)

	vals := r.Values()
	if len(vals) != 2 {
		t.Fatalf("Values() len = %d, want 2", len(vals))
	}
	if vals[0] > vals[1] {
		t.Errorf("Values() not sorted: %v", vals)
	}
}

// ---------------------------------------------------------------------------
// Live tab: source selector, focus transitions, Run button
// ---------------------------------------------------------------------------

func TestLiveSourceSelectorToggle(t *testing.T) {
	t.Parallel()

	sel := NewLiveSourceSelector().Focus().(LiveSourceSelector)
	if sel.Value() != "hubble" {
		t.Fatalf("default source = %q, want hubble", sel.Value())
	}

	// Move cursor down and select Calico.
	updated, _ := sel.Update(tea.KeyMsg{Type: tea.KeyDown})
	sel = updated.(LiveSourceSelector)
	updated, _ = sel.Update(tea.KeyMsg{Type: tea.KeySpace})
	sel = updated.(LiveSourceSelector)

	if sel.Value() != "calico" {
		t.Errorf("after toggle: source = %q, want calico", sel.Value())
	}

	// Move cursor back up and select Hubble.
	updated, _ = sel.Update(tea.KeyMsg{Type: tea.KeyUp})
	sel = updated.(LiveSourceSelector)
	updated, _ = sel.Update(tea.KeyMsg{Type: tea.KeySpace})
	sel = updated.(LiveSourceSelector)

	if sel.Value() != "hubble" {
		t.Errorf("after re-toggle: source = %q, want hubble", sel.Value())
	}
}

func TestLiveFocusTransitionsViaModel(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, activeArea: AreaLiveSelector}
	m.liveTab = NewLiveTab()
	if m.liveTab.focusIndex != 0 {
		t.Fatalf("initial focusIndex = %d, want 0", m.liveTab.focusIndex)
	}

	// Tab cycles areas: selector(0) → input(1) → button(2) → selector(0).
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated := model.(Model)
	if updated.activeArea != AreaLiveInput {
		t.Errorf("after tab from selector: activeArea = %v, want AreaLiveInput", updated.activeArea)
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated = model.(Model)
	if updated.activeArea != AreaLiveForm {
		t.Errorf("after tab from input: activeArea = %v, want AreaLiveForm", updated.activeArea)
	}

	// Verify selector still responds to its own keys (up wraps to bottom).
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	updated = model.(Model)
	if updated.activeArea != AreaLiveSelector {
		t.Errorf("up from selector kept area = %v, want AreaLiveSelector", updated.activeArea)
	}
}

func TestLiveRunButtonEmitsLiveRunMsg(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, activeArea: AreaLiveButton}
	m.liveTab = NewLiveTab()
	m.liveTab.focusIndex = 2

	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	msg := cmd()
	if _, ok := msg.(LiveRunMsg); !ok {
		t.Errorf("cmd returned %T, want LiveRunMsg", msg)
	}

	updated, _ := model.(Model)
	model2, _ := updated.Update(msg)
	updated = model2.(Model)
	if !updated.liveRunning {
		t.Error("liveRunning should be true after LiveRunMsg")
	}
}

// ---------------------------------------------------------------------------
// Simulate tab: focus cycling through all fields
// ---------------------------------------------------------------------------

func TestSimulateTabForwardCycling(t *testing.T) {
	t.Parallel()

	cases := []struct {
		from Area
		want Area
	}{
		{AreaSimPolicyDir, AreaSimSrc},
		{AreaSimSrc, AreaSimDst},
		{AreaSimDst, AreaSimInputs},
		{AreaSimInputs, AreaSimEval},
		{AreaSimEval, AreaSimPolicyDir},
	}

	for _, c := range cases {
		m := Model{activeTab: TabSimulate, activeArea: c.from, policyDirPicked: true}
		m.initInputs()
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		updated := model.(Model)
		if updated.activeArea != c.want {
			t.Errorf("Tab from %v: got %v, want %v", c.from, updated.activeArea, c.want)
		}
	}
}

func TestSimulateTabReverseCycling(t *testing.T) {
	t.Parallel()

	cases := []struct {
		from Area
		want Area
	}{
		{AreaSimEval, AreaSimInputs},
		{AreaSimInputs, AreaSimDst},
		{AreaSimDst, AreaSimSrc},
		{AreaSimSrc, AreaSimPolicyDir},
		{AreaSimPolicyDir, AreaSimEval},
	}

	for _, c := range cases {
		m := Model{activeTab: TabSimulate, activeArea: c.from, policyDirPicked: true}
		m.initInputs()
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
		updated := model.(Model)
		if updated.activeArea != c.want {
			t.Errorf("Shift+Tab from %v: got %v, want %v", c.from, updated.activeArea, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Bottom pane: ctrl+o, output focus, scroll keys
// ---------------------------------------------------------------------------

func TestCtrlOTogglesOutputFocus(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true}
	if m.outputFocused {
		t.Fatal("outputFocused should start false")
	}

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	// Ctrl+o is a special key, not 'o'.
	m2 := Model{activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true}
	model, _ = m2.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	updated := model.(Model)
	if !updated.outputFocused {
		t.Error("ctrl+o should set outputFocused=true")
	}

	model, _ = updated.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	updated = model.(Model)
	if updated.outputFocused {
		t.Error("ctrl+o should toggle outputFocused back to false")
	}
}

func TestOutputFocusedEscUnfocuses(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab:       TabSimulate,
		focusField_:     focusSrc,
		policyDirPicked: true,
		outputFocused:   true,
	}

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated := model.(Model)
	if updated.outputFocused {
		t.Error("esc should unfocus output pane")
	}
}

func TestOutputFocusedSwallowsUnrelatedKeys(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab:       TabSimulate,
		focusField_:     focusPort,
		policyDirPicked: true,
		outputFocused:   true,
	}

	model, _ := m.Update(keyMsg("a"))
	updated := model.(Model)
	// 'a' is swallowed when output is focused (not a scroll/tab/quit key).
	if updated.focusField_ != focusPort {
		t.Errorf("unrelated key changed focusField_ to %d", updated.focusField_)
	}
}

func TestOutputFocusedPassesTabNavigation(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab:     TabLive,
		outputFocused: true,
	}
	m.liveTab = NewLiveTab()

	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	updated := model.(Model)
	if updated.activeTab != TabSimulate {
		t.Errorf("Right while output focused: got %v, want TabSimulate", updated.activeTab)
	}
}

func TestOutputFocusedPassesQuit(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab:       TabSimulate,
		policyDirPicked: true,
		outputFocused:   true,
	}

	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	updated := model.(Model)
	if !updated.quitting {
		t.Error("ctrl+c should quit even when output is focused")
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}

// ---------------------------------------------------------------------------
// Help dialog: opens on ?/F1, closes on esc/q/?/F1, blocks input
// ---------------------------------------------------------------------------

func TestHelpOpensOnQuestionMark(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updated := model.(Model)
	if !updated.showHelp {
		t.Error("? should open help dialog")
	}
}

func TestHelpOpensOnF1(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyF1})
	updated := model.(Model)
	if !updated.showHelp {
		t.Error("F1 should open help dialog")
	}
}

func TestHelpClosesOnEsc(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated := model.(Model)
	if updated.showHelp {
		t.Error("esc should close help")
	}
}

func TestHelpClosesOnQ(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	updated := model.(Model)
	if updated.showHelp {
		t.Error("q should close help")
	}
	if updated.quitting {
		t.Error("q in help should not quit")
	}
}

func TestHelpClosesOnQuestionMark(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updated := model.(Model)
	if updated.showHelp {
		t.Error("? should toggle help closed")
	}
}

func TestHelpClosesOnF1(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyF1})
	updated := model.(Model)
	if updated.showHelp {
		t.Error("F1 should toggle help closed")
	}
}

func TestHelpBlocksOtherInput(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true, activeTab: TabSimulate, focusField_: focusSrc, policyDirPicked: true}
	model, _ := m.Update(keyMsg("a"))
	updated := model.(Model)
	if !updated.showHelp {
		t.Error("unrelated key should not close help")
	}
	// focusField_ should not change.
	if updated.focusField_ != focusSrc {
		t.Error("help should block focus changes")
	}
}

func TestHelpViewShowsShortcuts(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true, width: 80, height: 24}
	view := m.View()
	for _, substr := range []string{"Keyboard Shortcuts", "Switch tabs", "Quit"} {
		if !strings.Contains(view, substr) {
			t.Errorf("help view missing %q", substr)
		}
	}
}

// ---------------------------------------------------------------------------
// Overwrite dialog: opens/closes, blocks input, quit
// ---------------------------------------------------------------------------

func TestOverwriteAcceptsY(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	updated := model.(Model)
	if updated.showOverwrite {
		t.Error("y should close overwrite dialog")
	}
	if !updated.overwriteConfirmed {
		t.Error("y should confirm overwrite")
	}
}

func TestOverwriteAcceptsEnter(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated := model.(Model)
	if !updated.overwriteConfirmed {
		t.Error("enter should confirm overwrite")
	}
}

func TestOverwriteAcceptsCapitalY(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Y'}})
	updated := model.(Model)
	if !updated.overwriteConfirmed {
		t.Error("Y should confirm overwrite")
	}
}

func TestOverwriteRejectsN(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	updated := model.(Model)
	if updated.showOverwrite {
		t.Error("n should close overwrite dialog")
	}
	if updated.overwriteConfirmed {
		t.Error("n should not confirm overwrite")
	}
}

func TestOverwriteRejectsEsc(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated := model.(Model)
	if updated.overwriteConfirmed {
		t.Error("esc should not confirm overwrite")
	}
}

func TestOverwriteBlocksOtherInput(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out", activeTab: TabSimulate, focusField_: focusSrc}
	model, _ := m.Update(keyMsg("a"))
	updated := model.(Model)
	if !updated.showOverwrite {
		t.Error("unrelated key should not close overwrite dialog")
	}
	if updated.overwriteConfirmed {
		t.Error("unrelated key should not confirm overwrite")
	}
}

func TestOverwriteQuitsOnQ(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	updated := model.(Model)
	if !updated.quitting {
		t.Error("q in overwrite dialog should quit")
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("expected tea.Quit command")
	}
}

func TestOverwriteQuitsOnCtrlC(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/out"}
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	updated := model.(Model)
	if !updated.quitting {
		t.Error("ctrl+c in overwrite dialog should quit")
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}

// ---------------------------------------------------------------------------
// Focus descriptions: focusStatus() per-field descriptions
// ---------------------------------------------------------------------------

func TestFocusStatusAnalyzeTab(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, activeArea: AreaAnalyzePicker}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeTab.pickerFocused = true
	got := m.focusStatus()
	if !strings.Contains(got, "select flow source") {
		t.Errorf("focusStatus (picker) = %q, want 'select flow source'", got)
	}

	m2 := Model{activeTab: TabAnalyze, activeArea: AreaAnalyzeReports}
	m2.analyzeTab = NewAnalyzeTab()
	m2.analyzeTab.pickerFocused = false
	m2.analyzeReports = NewAnalyzeReports("Reports", "desc").Focus().(AnalyzeReports)
	got = m2.focusStatus()
	if !strings.Contains(got, "reports") {
		t.Errorf("focusStatus (reports) = %q, want 'reports'", got)
	}
}

func TestFocusStatusLiveTab(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive}
	got := m.focusStatus()
	if !strings.Contains(got, "Live") {
		t.Errorf("focusStatus = %q, want contains 'Live'", got)
	}
}

func TestFocusStatusSimulateTab(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, policyDirPicked: true, focusField_: focusSrc}
	got := m.focusStatus()
	if !strings.Contains(got, "Simulate") {
		t.Errorf("focusStatus = %q, want contains 'Simulate'", got)
	}
}

func TestFocusDescriptionSimulatePerField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		area Area
		want string
	}{
		{AreaSimSrc, "source"},
		{AreaSimDst, "destination"},
		{AreaSimInputs, "traffic"},
		{AreaSimEval, "Evaluate"},
	}
	for _, c := range cases {
		m := Model{activeTab: TabSimulate, policyDirPicked: true, activeArea: c.area}
		got := m.focusDescription()
		if !strings.Contains(strings.ToLower(got), strings.ToLower(c.want)) {
			t.Errorf("focusDescription(area=%v) = %q, want contains %q", c.area, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Status messages: setStatus
// ---------------------------------------------------------------------------

func TestSetStatusSetsFields(t *testing.T) {
	t.Parallel()

	m := Model{}
	m.setStatus("hello", 5)
	if m.statusMsg != "hello" {
		t.Errorf("statusMsg = %q, want hello", m.statusMsg)
	}
	if m.statusFrames != 5 {
		t.Errorf("statusFrames = %d, want 5", m.statusFrames)
	}
}

func TestSetStatusResetsPrevious(t *testing.T) {
	t.Parallel()

	m := Model{}
	m.setStatus("first", 10)
	m.setStatus("second", 3)
	if m.statusMsg != "second" {
		t.Errorf("statusMsg = %q, want second", m.statusMsg)
	}
	if m.statusFrames != 3 {
		t.Errorf("statusFrames = %d, want 3", m.statusFrames)
	}
}

// ---------------------------------------------------------------------------
// Done messages: analyzeDoneMsg / liveDoneMsg handlers
// ---------------------------------------------------------------------------

func TestAnalyzeDoneStoresOutput(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, analyzeRunning: true}
	model, _ := m.Update(analyzeDoneMsg{output: "analysis complete"})
	updated := model.(Model)
	if updated.analyzeRunning {
		t.Error("analyzeRunning should be false after done")
	}
	if updated.analyzeOutput != "analysis complete" {
		t.Errorf("analyzeOutput = %q, want 'analysis complete'", updated.analyzeOutput)
	}
}

func TestAnalyzeDoneStoresError(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, analyzeRunning: true}
	model, _ := m.Update(analyzeDoneMsg{output: "partial", err: fmt.Errorf("something failed")})
	updated := model.(Model)
	if updated.analyzeRunning {
		t.Error("analyzeRunning should be false after error")
	}
	if !strings.Contains(updated.analyzeOutput, "something failed") {
		t.Errorf("analyzeOutput should contain error, got %q", updated.analyzeOutput)
	}
}

func TestLiveDoneStoresOutput(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, liveRunning: true}
	model, _ := m.Update(liveDoneMsg{output: "stream ended"})
	updated := model.(Model)
	if updated.liveRunning {
		t.Error("liveRunning should be false after done")
	}
	if updated.liveOutput != "stream ended" {
		t.Errorf("liveOutput = %q, want 'stream ended'", updated.liveOutput)
	}
}

func TestLiveDoneStoresError(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, liveRunning: true}
	model, _ := m.Update(liveDoneMsg{output: "partial", err: fmt.Errorf("conn lost")})
	updated := model.(Model)
	if updated.liveRunning {
		t.Error("liveRunning should be false after error")
	}
	if !strings.Contains(updated.liveOutput, "conn lost") {
		t.Errorf("liveOutput should contain error, got %q", updated.liveOutput)
	}
}

func TestAnalyzeRunMsgSetsRunning(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze}
	m.analyzeTab = NewAnalyzeTab()
	// analyzeRunner is nil → cmd returns analyzeDoneMsg with error.
	model, cmd := m.Update(AnalyzeRunMsg{})
	updated := model.(Model)
	if !updated.analyzeRunning {
		t.Error("analyzeRunning should be true after AnalyzeRunMsg")
	}
	if updated.analyzeOutput != "" {
		t.Error("analyzeOutput should be cleared")
	}
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	// Execute cmd to get done message.
	doneMsg := cmd()
	model, _ = updated.Update(doneMsg)
	updated = model.(Model)
	if updated.analyzeRunning {
		t.Error("analyzeRunning should be false after done")
	}
	if !strings.Contains(updated.analyzeOutput, "analyze runner not configured") {
		t.Errorf("expected error in output, got %q", updated.analyzeOutput)
	}
}

func TestLiveRunMsgSetsRunning(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive}
	m.liveTab = NewLiveTab()
	m.liveTab.focusIndex = 2

	_, cmd := m.Update(LiveRunMsg{})
	updated := m
	if cmd == nil {
		t.Fatal("LiveRunMsg should return a command")
	}

	doneResult := cmd()
	model, _ := updated.Update(doneResult)
	updated = model.(Model)
	if updated.liveRunning {
		t.Error("liveRunning should be false after done")
	}
	if !strings.Contains(updated.liveOutput, "live runner not configured") {
		t.Errorf("expected error in output, got %q", updated.liveOutput)
	}
}

// ---------------------------------------------------------------------------
// Q key: quits only when not in a text input
// ---------------------------------------------------------------------------

func TestQKeyDoesNotQuitInTextInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		focus int
		name  string
	}{
		{focusPort, "port"},
		{focusProto, "proto"},
		{focusL7Name, "l7name"},
		{focusL7Pattern, "l7pattern"},
	}
	for _, c := range cases {
		m := Model{activeTab: TabSimulate, focusField_: c.focus, policyDirPicked: true}
		m.initInputs()
		model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		updated := model.(Model)
		if updated.quitting {
			t.Errorf("q in %s input should not quit", c.name)
		}
	}
}

func TestQKeyQuitsWhenNotInTextInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		focus int
		name  string
	}{
		{focusPolicyDir, "policyDir"},
		{focusSrc, "src"},
		{focusDst, "dst"},
		{focusEval, "eval"},
	}
	for _, c := range cases {
		m := Model{activeTab: TabSimulate, focusField_: c.focus, policyDirPicked: true}
		model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		updated := model.(Model)
		if !updated.quitting {
			t.Errorf("q on %s should quit", c.name)
		}
		if cmd == nil {
			t.Errorf("q on %s should return quit command", c.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Window size: viewport dimensions update
// ---------------------------------------------------------------------------

func TestWindowSizeUpdatesViewportDimensions(t *testing.T) {
	t.Parallel()

	m := Model{outputViewport: viewport.New(10, 5)}
	model, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	updated := model.(Model)
	if updated.width != 120 {
		t.Errorf("width = %d, want 120", updated.width)
	}
	if updated.height != 40 {
		t.Errorf("height = %d, want 40", updated.height)
	}
}

// ---------------------------------------------------------------------------
// View: tab labels, version, CLI preview, help, overwrite
// ---------------------------------------------------------------------------

func TestViewAllTabLabels(t *testing.T) {
	t.Parallel()

	for _, tab := range []Tab{TabAnalyze, TabLive, TabSimulate} {
		m := Model{activeTab: tab, width: 80, height: 24}
		m.analyzeTab = NewAnalyzeTab()
		m.analyzeReports = NewAnalyzeReports("Reports", "desc")
		m.liveTab = NewLiveTab()
		m.initInputs()
		view := m.View()
		for _, label := range []string{"Analyze", "Live", "Simulate"} {
			if !strings.Contains(view, label) {
				t.Errorf("View() on tab %v missing %q", tab, label)
			}
		}
	}
}

func TestViewVersionDisplayed(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, version: "2.0.0", width: 80, height: 24}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "desc")
	m.liveTab = NewLiveTab()
	m.initInputs()
	view := m.View()
	if !strings.Contains(view, "2.0.0") {
		t.Error("View() should contain version")
	}
}

func TestViewCLIPreviewOnAnalyze(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, width: 80, height: 24}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "desc")
	m.liveTab = NewLiveTab()
	m.initInputs()
	view := m.View()
	if !strings.Contains(view, "flowguarder") {
		t.Error("View() should contain CLI preview with flowguarder")
	}
}

func TestViewCLIPreviewOnSimulate(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, width: 80, height: 24, policyDirPicked: true}
	m.initInputs()
	m.policyDir = "/policies"
	view := m.View()
	if !strings.Contains(view, "simulate") {
		t.Error("View() should contain 'simulate' in CLI preview")
	}
}

func TestViewCLIPreviewOnLive(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, width: 80, height: 24}
	m.liveTab = NewLiveTab()
	m.initInputs()
	view := m.View()
	if !strings.Contains(view, "live") {
		t.Error("View() should contain 'live' in CLI preview")
	}
}

func TestViewHelpDialogContent(t *testing.T) {
	t.Parallel()

	m := Model{showHelp: true, width: 80, height: 24}
	view := m.View()
	if !strings.Contains(view, "Keyboard Shortcuts") {
		t.Error("help view should contain 'Keyboard Shortcuts'")
	}
	if !strings.Contains(view, "Ctrl+C") {
		t.Error("help view should contain 'Ctrl+C'")
	}
}

func TestViewOverwriteDialogContent(t *testing.T) {
	t.Parallel()

	m := Model{showOverwrite: true, overwritePath: "/output", width: 80, height: 24}
	view := m.View()
	if !strings.Contains(view, "Confirm Overwrite") {
		t.Error("overwrite view should contain 'Confirm Overwrite'")
	}
	if !strings.Contains(view, "/output") {
		t.Error("overwrite view should contain the path")
	}
}

func TestViewSimulateBodyShowsInputFields(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, width: 80, height: 24, policyDirPicked: true}
	m.initInputs()
	// Initialize with mock selectable objects so the lists are populated.
	m.InitModel(SelectableObjects{
		Workloads: []SelectableWorkload{
			{Namespace: "default", Name: "frontend", Labels: map[string]string{"app": "frontend"}},
		},
		Entities: []string{"world"},
		CIDRs:    []SelectableCIDR{{CIDR: "10.96.0.0/12", Desc: "service CIDR"}},
	}, ".", nil)
	view := m.View()
	for _, label := range []string{"Port:", "Proto:", "Evaluate"} {
		if !strings.Contains(view, label) {
			t.Errorf("View() missing %q", label)
		}
	}
}

func TestViewLiveBodyShowsSource(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, width: 80, height: 24}
	m.liveTab = NewLiveTab()
	m.initInputs()
	view := m.View()
	if !strings.Contains(view, "Hubble server") {
		t.Error("View() should show Hubble server option")
	}
}

// ---------------------------------------------------------------------------
// pushFocus / popFocus
// ---------------------------------------------------------------------------

func TestPushPopFocus(t *testing.T) {
	t.Parallel()

	m := Model{focusField_: focusSrc}
	m.pushFocus()
	if len(m.focusStack) != 1 {
		t.Fatalf("focusStack len = %d, want 1", len(m.focusStack))
	}
	if m.focusDepth != 1 {
		t.Fatalf("focusDepth = %d, want 1", m.focusDepth)
	}

	m.focusField_ = focusDst
	m.pushFocus()
	if m.focusDepth != 2 {
		t.Fatalf("focusDepth = %d, want 2", m.focusDepth)
	}

	f := m.popFocus()
	if f != focusDst {
		t.Errorf("popFocus() = %d, want %d", f, focusDst)
	}
	f = m.popFocus()
	if f != focusSrc {
		t.Errorf("popFocus() = %d, want %d", f, focusSrc)
	}
}

func TestPushPopFocusEmptyStack(t *testing.T) {
	t.Parallel()

	m := Model{}
	f := m.popFocus()
	if f != focusTabBar {
		t.Errorf("popFocus() on empty stack = %d, want %d", f, focusTabBar)
	}
}

// ---------------------------------------------------------------------------
// isTextInputFocused
// ---------------------------------------------------------------------------

func TestIsTextInputFocused(t *testing.T) {
	t.Parallel()

	textInputs := []struct {
		focus int
		name  string
	}{
		{focusPort, "port"},
		{focusProto, "proto"},
		{focusL7Name, "l7Name"},
		{focusL7Pattern, "l7Pattern"},
	}
	for _, c := range textInputs {
		m := Model{focusField_: c.focus}
		if !m.isTextInputFocused() {
			t.Errorf("isTextInputFocused(%s) = false, want true", c.name)
		}
	}

	nonTextInputs := []struct {
		focus int
		name  string
	}{
		{focusPolicyDir, "policyDir"},
		{focusSrc, "src"},
		{focusDst, "dst"},
		{focusEval, "eval"},
	}
	for _, c := range nonTextInputs {
		m := Model{focusField_: c.focus}
		if m.isTextInputFocused() {
			t.Errorf("isTextInputFocused(%s) = true, want false", c.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Simulate tab: arrow key navigation within input fields
// ---------------------------------------------------------------------------

func TestSimulateArrowKeyNavigation(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, activeArea: AreaSimInputs, focusField_: focusPort, policyDirPicked: true}
	m.initInputs()
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	updated := model.(Model)
	if updated.focusField_ != focusPort {
		t.Errorf("up from port: got %d, want %d (no-op, port is first input)", updated.focusField_, focusPort)
	}

	m = Model{activeTab: TabSimulate, activeArea: AreaSimInputs, focusField_: focusPort, policyDirPicked: true}
	m.initInputs()
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	updated = model.(Model)
	if updated.focusField_ != focusProto {
		t.Errorf("down from port: got %d, want %d", updated.focusField_, focusProto)
	}
}

// ---------------------------------------------------------------------------
// Eval button: pressing enter triggers evaluation
// ---------------------------------------------------------------------------

func TestEvalButtonTriggersEvaluation(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate, activeArea: AreaSimEval, policyDirPicked: true}
	m.initInputs()
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated := model.(Model)
	if cmd == nil {
		t.Fatal("enter on eval should return a command")
	}
	evalMsg := cmd()
	done, ok := evalMsg.(evalDoneMsg)
	if !ok {
		t.Fatalf("expected evalDoneMsg, got %T", evalMsg)
	}
	if done.err == nil {
		t.Error("expected error with empty source/destination")
	}

	model, _ = updated.Update(done)
	updated = model.(Model)
	if updated.err == nil {
		t.Error("error should be stored after evalDoneMsg with error")
	}
}

// ---------------------------------------------------------------------------
// Bottom pane: output content per tab
// ---------------------------------------------------------------------------

func TestBottomOutputContentSimulateDefault(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabSimulate}
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Select source") {
		t.Errorf("default simulate output = %q, want 'Select source'", got)
	}
}

func TestBottomOutputContentSimulateWithResult(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab: TabSimulate,
		result:    &ResultData{Ingress: "allow", Egress: "deny"},
	}
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Ingress") {
		t.Errorf("result view should contain 'Ingress', got %q", got)
	}
}

func TestBottomOutputContentSimulateWithError(t *testing.T) {
	t.Parallel()

	m := Model{
		activeTab: TabSimulate,
		err:       fmt.Errorf("test error"),
	}
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Error") {
		t.Errorf("error view should contain 'Error', got %q", got)
	}
}

func TestBottomOutputContentAnalyze(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze}
	m.analyzeTab = NewAnalyzeTab()
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Analyze options (preview)") {
		t.Errorf("analyze preview = %q, want 'Analyze options (preview)'", got)
	}
}

func TestBottomOutputContentLive(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive}
	m.liveTab = NewLiveTab()
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Live options (preview)") {
		t.Errorf("live preview = %q, want 'Live options (preview)'", got)
	}
}

func TestBottomOutputContentAnalyzeRunning(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabAnalyze, analyzeRunning: true}
	m.analyzeTab = NewAnalyzeTab()
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Running") {
		t.Errorf("running preview = %q, want 'Running'", got)
	}
}

func TestBottomOutputContentLiveRunning(t *testing.T) {
	t.Parallel()

	m := Model{activeTab: TabLive, liveRunning: true}
	m.liveTab = NewLiveTab()
	got := m.bottomOutputContent()
	if !strings.Contains(got, "Running") {
		t.Errorf("running preview = %q, want 'Running'", got)
	}
}

// ---------------------------------------------------------------------------
// View: active tab highlight
// ---------------------------------------------------------------------------

func TestViewActiveTabHighlighted(t *testing.T) {
	t.Parallel()

	// The active tab should appear with brackets [Tab].
	m := Model{activeTab: TabAnalyze, width: 80, height: 24}
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "desc")
	m.liveTab = NewLiveTab()
	m.initInputs()
	view := m.View()
	if !strings.Contains(view, "[Analyze]") {
		t.Error("active Analyze tab should be highlighted with brackets")
	}
}

// ---------------------------------------------------------------------------
// Live tab: ViewWithState shows Running text when liveRunning
// ---------------------------------------------------------------------------

func TestLiveViewWithStateRunning(t *testing.T) {
	t.Parallel()

	tab := NewLiveTab()
	got := tab.ViewWithState(true, 0, 0)
	if !strings.Contains(got, "Running") {
		t.Errorf("ViewWithState(running=true) = %q, want 'Running'", got)
	}
}

func TestLiveViewWithStateIdle(t *testing.T) {
	t.Parallel()

	tab := NewLiveTab()
	got := tab.ViewWithState(false, 0, 0)
	if strings.Contains(got, "Running") {
		t.Errorf("ViewWithState(running=false) should not contain 'Running'")
	}
}

// ---------------------------------------------------------------------------
// Live tab: UpdateWithState
// ---------------------------------------------------------------------------

func TestLiveUpdateWithStateEscFromRunButton(t *testing.T) {
	t.Parallel()

	tab := NewLiveTab()
	tab.focusIndex = 2

	updated, _ := tab.UpdateWithState(tea.KeyMsg{Type: tea.KeyEsc}, true)
	if updated.focusIndex != 1 {
		t.Errorf("esc from run button: focusIndex = %d, want 1", updated.focusIndex)
	}
}

func TestLiveUpdateWithStateRunButtonBlocksKeys(t *testing.T) {
	t.Parallel()

	tab := NewLiveTab()
	tab.focusIndex = 2

	updated, cmd := tab.UpdateWithState(keyMsg("a"), true)
	if cmd != nil {
		t.Error("keys on run button while running should be blocked")
	}
	_ = updated
}

// ---------------------------------------------------------------------------
// Analyze reports: report types are the fixed set
// ---------------------------------------------------------------------------

func TestAnalyzeReportTypesFixedSet(t *testing.T) {
	t.Parallel()

	expected := map[string]bool{
		"top-flows": true, "uncovered": true, "coverage": true,
		"egress-world": true, "drops": true, "anomalies": true,
	}
	for _, rt := range analyzeReportTypes {
		if !expected[rt] {
			t.Errorf("unexpected report type %q", rt)
		}
		delete(expected, rt)
	}
	if len(expected) > 0 {
		t.Errorf("missing report types: %v", expected)
	}
}

// ---------------------------------------------------------------------------
// bottomViewportHeight
// ---------------------------------------------------------------------------

func TestBottomViewportHeight(t *testing.T) {
	t.Parallel()

	cases := []struct {
		height int
		want   int
	}{
		{0, 5},
		{10, 5},
		{30, 5},
		{60, 12},
	}
	for _, c := range cases {
		m := Model{height: c.height}
		got := m.bottomViewportHeight()
		if got != c.want {
			t.Errorf("bottomViewportHeight(height=%d) = %d, want %d", c.height, got, c.want)
		}
	}
}
