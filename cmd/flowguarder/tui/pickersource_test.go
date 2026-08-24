package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// newPickerSourceModel builds an Analyze-tab Model pointed at dir with the
// picker listing loaded (Init → readDirMsg → Update), mirroring the deleted
// zz_sel_test scaffolding.
func newPickerSourceModel(t *testing.T, dir string) Model {
	t.Helper()
	at := NewAnalyzeTab()
	at.picker.CurrentDirectory = dir
	at.picker.Path = "."
	if cmd := at.picker.Init(); cmd != nil {
		if msg := cmd(); msg != nil {
			at.picker, _ = at.picker.Update(msg)
		}
	}
	m := Model{
		analyzeTab: at,
		activeTab:  TabAnalyze,
		activeArea: AreaAnalyzePicker,
		width:      120,
		height:     40,
	}
	m.analyzeTab.pickerFocused = true
	m.analyzeTab.pickerCursorPos = 0 // start on the synthetic ".." row
	m.analyzeTab.refreshDirEntries()
	return m
}

// TestPickerSourceTracksHighlight verifies the highlighted entry IS the
// source: arrows alone drive Values()["Source"] without any Enter press.
func TestPickerSourceTracksHighlight(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Sorted listing (dirs first): [sub, flows.jsonl] → pos 1=sub, pos 2=flows.jsonl.
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("CaseB_pos0_returns_browsed_dir", func(t *testing.T) {
		t.Parallel()
		m := newPickerSourceModel(t, dir)
		m.analyzeTab.pickerCursorPos = 0
		if got := m.analyzeTab.Values()["Source"]; got != dir {
			t.Errorf("Values()[\"Source\"] = %q, want %q", got, dir)
		}
	})

	t.Run("CaseA_highlight_file_no_enter", func(t *testing.T) {
		t.Parallel()
		m := newPickerSourceModel(t, dir)
		m.analyzeTab.pickerCursorPos = 2 // flows.jsonl
		want := filepath.Join(dir, "flows.jsonl")
		if got := m.analyzeTab.Values()["Source"]; got != want {
			t.Errorf("Values()[\"Source\"] = %q, want %q (highlight must drive source without Enter)", got, want)
		}
	})

	t.Run("CaseA_highlight_dir_no_enter", func(t *testing.T) {
		t.Parallel()
		m := newPickerSourceModel(t, dir)
		m.analyzeTab.pickerCursorPos = 1 // sub
		want := filepath.Join(dir, "sub")
		if got := m.analyzeTab.Values()["Source"]; got != want {
			t.Errorf("Values()[\"Source\"] = %q, want %q", got, want)
		}
	})
}

// TestPickerSourceEnterConsistent verifies Enter keeps working as today:
// picker.Path and Values()["Source"] agree on the entered file.
func TestPickerSourceEnterConsistent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := newPickerSourceModel(t, dir)
	// Key-driven navigation keeps the synthetic cursor in sync with the
	// bubbles internal cursor: down (pos0→1, early return), down (pos1→2,
	// bubbles selected 0→1 → flows.jsonl).
	m, _ = m.updateAnalyze(tea.KeyMsg{Type: tea.KeyDown})
	m, _ = m.updateAnalyze(tea.KeyMsg{Type: tea.KeyDown})
	nm, _ := m.updateAnalyze(tea.KeyMsg{Type: tea.KeyEnter})

	want := filepath.Join(dir, "flows.jsonl")
	if nm.analyzeTab.picker.Path != want {
		t.Errorf("picker.Path = %q, want %q", nm.analyzeTab.picker.Path, want)
	}
	if got := nm.analyzeTab.Values()["Source"]; got != want {
		t.Errorf("Values()[\"Source\"] = %q, want %q after Enter", got, want)
	}
}

// TestPickerSourceDescentRefresh verifies refreshDirEntries fires on descent:
// after entering sub/, highlighting its content yields sub-relative paths.
func TestPickerSourceDescentRefresh(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newPickerSourceModel(t, dir)
	m, _ = m.updateAnalyze(tea.KeyMsg{Type: tea.KeyDown}) // pos 1 = sub (dirs first)
	nm, _ := m.updateAnalyze(tea.KeyMsg{Type: tea.KeyEnter})

	if got := nm.analyzeTab.picker.CurrentDirectory; got != filepath.Join(dir, "sub") {
		t.Fatalf("CurrentDirectory = %q, want %q", got, filepath.Join(dir, "sub"))
	}
	if len(nm.analyzeTab.dirEntries) != 1 || nm.analyzeTab.dirEntries[0].Name() != "inner.jsonl" {
		t.Fatalf("dirEntries not refreshed on descent: %+v", nm.analyzeTab.dirEntries)
	}

	// Highlight inner.jsonl inside sub/ (pos 0→1, early return keeps bubbles cursor at 0).
	nm, _ = nm.updateAnalyze(tea.KeyMsg{Type: tea.KeyDown})
	want := filepath.Join(dir, "sub", "inner.jsonl")
	if got := nm.analyzeTab.Values()["Source"]; got != want {
		t.Errorf("Values()[\"Source\"] = %q, want %q after descent+highlight", got, want)
	}
}

// TestHandleAnalyzeRunUsesHighlightedEntry locks the end-to-end chain fixed by
// dc1d7f1: highlighting a flow file with ARROWS ONLY (no Enter) and pressing
// Run must pass THAT FILE's path as sourcePath to the analyze runner.
//
// Documented-red: on pre-dc1d7f1 code AnalyzeTab.Values() resolved "Source"
// from picker.Path, which only updates on Enter — after arrow navigation it
// stayed ".", so gotSource would be "." instead of <dir>/flows.jsonl and the
// source badge showed "current directory". This test would have failed there.
func TestHandleAnalyzeRunUsesHighlightedEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	flowFile := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(flowFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newPickerSourceModel(t, dir)
	m.activeArea = AreaAnalyzeRun // Run button focused; NO Enter pressed in picker
	// Synthetic cursor: pos 0 = "..", pos 1 = first real entry = flows.jsonl.
	m.analyzeTab.pickerCursorPos = 1

	var gotSource string
	m.analyzeRunner = func(sourcePath, outputDir, format, policyFormat string, strict, defaultDeny, cilium bool, reports []string, topN int, vizLayout string) (string, error) {
		gotSource = sourcePath
		return "ok", nil
	}

	msg := m.handleAnalyzeRun()()
	done, ok := msg.(analyzeDoneMsg)
	if !ok {
		t.Fatalf("expected analyzeDoneMsg, got %T", msg)
	}
	if done.err != nil {
		t.Fatalf("runner error: %v", done.err)
	}
	if !strings.Contains(done.output, "ok") {
		t.Errorf("output %q does not mention success", done.output)
	}
	if gotSource != flowFile {
		t.Errorf("runner got sourcePath %q, want %q (highlight must drive source without Enter)", gotSource, flowFile)
	}
}

// --- Model-level key-driver repros for the "current directory" badge bug ---
//
// User flow: highlight a root-level flow file with ARROWS ONLY in the Analyze
// picker (CurrentDirectory == "."), press Run → HTML badge showed "current
// directory" (vizSourceLabel received "."). These tests drive the FULL
// top-level Model.Update like RunUnified does, with an injected analyzeRunner.
// t.Chdir pins CurrentDirectory "." to the fixture (the bug only exists at
// "."), which is incompatible with parallel subtests.

// newRunnerDriveModel builds a full unified Model exactly like RunUnified,
// chdir'd into dir so picker CurrentDirectory "." resolves to the fixture.
func newRunnerDriveModel(t *testing.T, dir string) (Model, *[]string) {
	t.Helper()
	t.Chdir(dir)

	m := Model{
		version:    "test",
		activeTab:  TabAnalyze,
		configPath: "",
	}
	m.outputViewport = viewport.New(80, 5)
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "Select report sections to generate").Focus().(AnalyzeReports)
	m.initInputs()
	m.initSimulatePicker()
	m.liveTab = NewLiveTab()
	m.analyzeRunButton = NewRunButton("Run")

	got := &[]string{}
	m.analyzeRunner = func(sourcePath, outputDir, format, policyFormat string, strict, defaultDeny, cilium bool, reports []string, topN int, vizLayout string) (string, error) {
		*got = append(*got, sourcePath)
		return "ok", nil
	}

	m.width, m.height = 200, 50
	if cmd := m.analyzeTab.picker.Init(); cmd != nil {
		if msg := cmd(); msg != nil {
			m.analyzeTab.picker, _ = m.analyzeTab.picker.Update(msg)
		}
	}
	m.analyzeTab.refreshDirEntries()
	return m, got
}

func driveKeys(m Model, keys ...tea.KeyMsg) Model {
	for _, k := range keys {
		upd, _ := m.Update(k)
		m = upd.(Model)
	}
	return m
}

func keyDown() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func keyUp() tea.KeyMsg    { return tea.KeyMsg{Type: tea.KeyUp} }
func keyEnter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }

// highlightedEntryName returns the entry on the cursor (">") line of the raw
// bubbles picker view — what the user sees highlighted.
func highlightedEntryName(t *testing.T, m Model) string {
	t.Helper()
	pv := safeFilePickerView(m.analyzeTab.picker)
	for _, line := range strings.Split(pv, "\n") {
		if strings.Contains(line, m.analyzeTab.picker.Cursor) {
			fields := strings.Fields(strings.ReplaceAll(line, "\x1b[0m", ""))
			if len(fields) == 0 {
				return ""
			}
			return fields[len(fields)-1]
		}
	}
	return ""
}

// runToRunButton Tabs three times (Picker→Reports→Form→Run) asserting landing.
func runToRunButton(t *testing.T, m Model) Model {
	t.Helper()
	for i := 0; i < 3; i++ {
		m = driveKeys(m, tea.KeyMsg{Type: tea.KeyTab})
	}
	if m.activeArea != AreaAnalyzeRun {
		t.Fatalf("after 3×Tab activeArea = %v, want AreaAnalyzeRun", m.activeArea)
	}
	return m
}

// TestReproBadgeDownUpShowsCurrentDirectory is the minimal arrow-only repro:
// at CurrentDirectory == "." (no ".." row rendered), ↓ then ↑ leaves the FIRST
// ENTRY visibly highlighted while pickerCursorPos lands back on the phantom
// ".." slot (pos 0), so Values()["Source"] — and therefore the Run badge —
// silently becomes "." even though a file is highlighted on screen.
func TestReproBadgeDownUpShowsCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	flowFile := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(flowFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, got := newRunnerDriveModel(t, dir)

	// Sanity: fresh state must already agree — screen highlights entry 0.
	if hl := highlightedEntryName(t, m); hl != "flows.jsonl" {
		t.Fatalf("fresh highlight = %q, want flows.jsonl", hl)
	}
	// At CD == "." sourceSelection returns relative joins: Join(".", x) = x.
	if src := m.analyzeTab.Values()["Source"]; src != "flows.jsonl" {
		t.Fatalf("fresh Source = %q, want %q (screen shows flows.jsonl highlighted)", src, "flows.jsonl")
	}

	m = driveKeys(m, keyDown(), keyUp())

	// The screen still highlights flows.jsonl...
	if hl := highlightedEntryName(t, m); hl != "flows.jsonl" {
		t.Fatalf("after ↓↑ highlight = %q, want flows.jsonl", hl)
	}
	// ...so Source must be flows.jsonl, not "." (pre-fix: ".").
	if src := m.analyzeTab.Values()["Source"]; src != "flows.jsonl" {
		t.Errorf("after ↓↑ Values()[\"Source\"] = %q, want %q (visually highlighted file)", src, "flows.jsonl")
	}

	// End-to-end: Run via top-level Update must pass the highlighted file.
	m = runToRunButton(t, m)
	upd, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = upd.(Model)
	if cmd == nil {
		t.Fatal("enter on Run returned nil cmd")
	}
	msg := cmd()
	done, ok := msg.(analyzeDoneMsg)
	if !ok {
		t.Fatalf("expected analyzeDoneMsg, got %T", msg)
	}
	if done.err != nil {
		t.Fatalf("runner error: %v", done.err)
	}
	if len(*got) != 1 {
		t.Fatalf("runner invoked %d times, want 1", len(*got))
	}
	if (*got)[0] != "flows.jsonl" {
		t.Errorf("runner got sourcePath %q, want %q (badge showed current directory pre-fix)", (*got)[0], "flows.jsonl")
	}
}

// TestReproBadgeOvershootShowsCurrentDirectory reproduces the user's likely
// flow: hammering ↓ to reach a jsonl near the bottom of the repo-root listing
// and overshooting the end. Pre-fix, pickerCursorPos grows unbounded past the
// last entry while the visible cursor clamps to the LAST ENTRY (a file), and
// sourceSelection falls back to the stale picker.Path (".").
func TestReproBadgeOvershootShowsCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	flowFile := filepath.Join(dir, "flows.jsonl")
	if err := os.WriteFile(flowFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	m, got := newRunnerDriveModel(t, dir)

	// 8 downs over a 2-entry listing — massive overshoot.
	keys := make([]tea.KeyMsg, 8)
	for i := range keys {
		keys[i] = keyDown()
	}
	m = driveKeys(m, keys...)

	// Visible cursor clamped to the last entry (flows.jsonl).
	if hl := highlightedEntryName(t, m); hl != "flows.jsonl" {
		t.Fatalf("after overshoot highlight = %q, want flows.jsonl", hl)
	}
	if src := m.analyzeTab.Values()["Source"]; src != "flows.jsonl" {
		t.Errorf("after overshoot Values()[\"Source\"] = %q, want %q (stale fallback pre-fix)", src, "flows.jsonl")
	}

	m = runToRunButton(t, m)
	upd, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = upd.(Model)
	if cmd == nil {
		t.Fatal("enter on Run returned nil cmd")
	}
	done := cmd().(analyzeDoneMsg)
	if done.err != nil {
		t.Fatalf("runner error: %v", done.err)
	}
	if len(*got) != 1 || (*got)[0] != "flows.jsonl" {
		t.Errorf("runner got sourcePath %v, want [%q]", *got, "flows.jsonl")
	}
}

// TestCursorSourceInvariantUnderNavigation asserts after EVERY navigation key
// that the visually highlighted entry equals Values()["Source"] — covering g,
// G, pgup/pgdown (K/J), boundary clamps and the pos==0 freeze at CD == ".".
func TestCursorSourceInvariantUnderNavigation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Listing (dirs first): [sub, flows.jsonl].

	m, _ := newRunnerDriveModel(t, dir)

	type step struct {
		name string
		key  tea.KeyMsg
		want string // expected highlighted entry after the key
	}
	// Fresh state at CD == "." starts on the first entry (pos 1 = sub).
	steps := []step{
		{"down→flows", keyDown(), "flows.jsonl"},
		{"down clamps at end", keyDown(), "flows.jsonl"},
		{"down clamps again", keyDown(), "flows.jsonl"},
		{"up→sub", keyUp(), "sub"},
		{"up clamps at first (never phantom ..)", keyUp(), "sub"},
		{"up clamps again", keyUp(), "sub"},
		{"g stays on first", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}}, "sub"},
		{"G jumps to last", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}}, "flows.jsonl"},
		{"pgup (K) back to first", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'K'}}, "sub"},
		{"pgdown (J) to last", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'J'}}, "flows.jsonl"},
		{"up→sub again", keyUp(), "sub"},
	}

	for _, s := range steps {
		m = driveKeys(m, s.key)
		hl := highlightedEntryName(t, m)
		src := m.analyzeTab.Values()["Source"]
		if hl != s.want {
			t.Errorf("%s: highlight = %q, want %q", s.name, hl, s.want)
		}
		if src != s.want {
			t.Errorf("%s: Source = %q, want %q (highlight/source divergence)", s.name, src, s.want)
		}
	}
}

// TestOverlayDirStillHasDotDotRow guards the non-"." behavior this fix must
// preserve: in a regular subdirectory the synthetic ".." row exists, pos==0
// maps to it, enter ascends, and arrows keep highlight/source in sync.
func TestOverlayDirStillHasDotDotRow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, _ := newRunnerDriveModel(t, dir)
	// Fresh highlight at "." is already the first entry (sub); enter descends.
	// Join(".", "sub") = "sub".
	m = driveKeys(m, keyEnter())
	if got := m.analyzeTab.picker.CurrentDirectory; got != "sub" {
		t.Fatalf("CurrentDirectory = %q, want %q", got, "sub")
	}

	// Fresh landing: pos 0 = ".." row, Source = browsed directory.
	if src := m.analyzeTab.Values()["Source"]; src != "sub" {
		t.Errorf("landed Source = %q, want browsed dir %q", src, "sub")
	}

	// Down → inner.jsonl highlighted; up → back to ".." (browsed dir).
	m = driveKeys(m, keyDown())
	if src := m.analyzeTab.Values()["Source"]; src != filepath.Join("sub", "inner.jsonl") {
		t.Errorf("after down Source = %q, want inner.jsonl", src)
	}
	m = driveKeys(m, keyUp())
	if src := m.analyzeTab.Values()["Source"]; src != "sub" {
		t.Errorf("after up Source = %q, want browsed dir %q (.. row)", src, "sub")
	}

	// Enter on ".." ascends back to the fixture root (Dir("sub") = ".").
	m = driveKeys(m, keyEnter())
	if got := m.analyzeTab.picker.CurrentDirectory; got != "." {
		t.Errorf("after ascend CurrentDirectory = %q, want %q", got, ".")
	}
	// Ascending into "." must land on the first real entry, not the phantom "..".
	if src := m.analyzeTab.Values()["Source"]; src != "sub" {
		t.Errorf("after ascend Source = %q, want first entry %q", src, "sub")
	}
}
