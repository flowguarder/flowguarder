// Package tui provides an interactive terminal UI for flowguarder simulate.
package tui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/simulate"
	yamlutil "sigs.k8s.io/yaml"
)

// SelectableObjects holds the data available for picker selection in the TUI.
type SelectableObjects struct {
	Workloads []SelectableWorkload // workloads extracted from the policy directory
	Entities  []string             // Cilium reserved entities (world, cluster, host, remote-node, kube-apiserver)
	CIDRs     []SelectableCIDR     // CIDR ranges extracted from the policy directory
}

// SelectableWorkload represents a workload that can be picked as source or destination.
type SelectableWorkload struct {
	Namespace string            // e.g. "default"
	Name      string            // e.g. "frontend"
	Labels    map[string]string // pod labels
	IP        string            // optional pod IP
	Entity    string            // optional Cilium reserved entity
}

// SelectableCIDR represents a CIDR range that can be picked as source or destination.
type SelectableCIDR struct {
	CIDR   string // e.g. "10.96.0.0/12"
	Desc   string // optional description
	Entity string // optional Cilium reserved entity name (world, cluster, etc.)
}

// ResultData holds the result of a simulation evaluation.
type ResultData struct {
	Ingress       string   // ingress verdict: "allow", "deny", or "undetermined"
	Egress        string   // egress verdict: "allow", "deny", or "undetermined"
	MatchingFiles []string // sorted matching policy file paths
}

// LiveRunMsg is emitted when the Live tab's Run button is activated. The
// handleLiveRun method acts on it to start the live pipeline.
type LiveRunMsg struct{}

// liveDoneMsg is sent when the live pipeline completes (stream ends, error,
// or context cancellation). It carries the captured output and any error.
type liveDoneMsg struct {
	output string
	err    error
}

// analyzeDoneMsg is sent when the analyze pipeline completes. It carries the
// captured output and any error.
type analyzeDoneMsg struct {
	output string
	err    error
}

// policyLoadedMsg is the message sent when policy loading completes.
type policyLoadedMsg struct {
	objects   SelectableObjects
	policyDir string
	policies  []simulate.LoadedPolicy
	err       error
}

// LiveRunner executes the live pipeline and returns captured output + error.
// Injected by the CLI layer (package main) to bridge the package boundary.
type LiveRunner func(ctx context.Context, source LiveSource, address, outputDir, format, policyFormat string, strict, defaultDeny bool, reports []string, vizLayout string) (string, error)

// AnalyzeRunner executes the analyze pipeline and returns captured output + error.
type AnalyzeRunner func(sourcePath, outputDir, format, policyFormat string, strict, defaultDeny, cilium bool, reports []string, topN int, vizLayout string) (string, error)

// PolicyLoader loads policies from a directory and extracts selectable objects.
// Injected by the CLI layer to avoid I/O in the TUI package.
type PolicyLoader func(dir string) ([]simulate.LoadedPolicy, SelectableObjects, error)

// Tab identifies one of the three top-level tabs in the unified TUI.
type Tab int

const (
	TabAnalyze Tab = iota
	TabLive
	TabSimulate
)

// Area identifies a focusable area within a tab.
type Area int

// Analyze tab areas.
const (
	AreaAnalyzePicker Area = iota
	AreaAnalyzeReports
	AreaAnalyzeForm
	AreaAnalyzeRun
)

// Live tab areas.
const (
	AreaLiveSelector Area = iota
	AreaLiveInput
	AreaLiveReports
	AreaLiveForm
	AreaLiveButton
)

// Simulate tab areas.
const (
	AreaSimPolicyDir Area = iota
	AreaSimSrc
	AreaSimDst
	AreaSimInputs
	AreaSimEval
)

// areaCount returns the number of areas for the given tab.
func areaCount(t Tab) int {
	switch t {
	case TabAnalyze:
		return 4
	case TabLive:
		return 5
	case TabSimulate:
		return 5
	}
	return 1
}

// areaForTab returns the first area index for the given tab.
func areaForTab(t Tab) Area {
	switch t {
	case TabAnalyze:
		return AreaAnalyzePicker
	case TabLive:
		return AreaLiveSelector
	case TabSimulate:
		return AreaSimPolicyDir
	}
	return AreaAnalyzePicker
}

// cycleArea moves the area forward (dir=1) or backward (dir=-1) within the
// current tab, wrapping.
func (m *Model) cycleArea(dir int) {
	// Capture selection before leaving source/destination areas in Simulate tab
	if m.activeTab == TabSimulate {
		switch m.activeArea {
		case AreaSimSrc:
			m.captureSrcSelection()
		case AreaSimDst:
			m.captureDstSelection()
		}
	}
	n := areaCount(m.activeTab)
	a := int(m.activeArea) + dir
	if a < 0 {
		a = n - 1
	} else if a >= n {
		a = 0
	}
	m.activeArea = Area(a)
}

// captureSrcSelection captures the currently highlighted source item.
func (m *Model) captureSrcSelection() {
	if m.srcListInit && len(m.srcList.Items()) > 0 {
		if idx := m.srcList.Index(); idx >= 0 {
			items := m.srcList.Items()
			if idx < len(items) {
				if item, ok := items[idx].(selectableItem); ok {
					m.srcItem = item
					m.srcSelected = true
				}
			}
		}
	}
}

// captureDstSelection captures the currently highlighted destination item.
func (m *Model) captureDstSelection() {
	if m.dstListInit && len(m.dstList.Items()) > 0 {
		if idx := m.dstList.Index(); idx >= 0 {
			items := m.dstList.Items()
			if idx < len(items) {
				if item, ok := items[idx].(selectableItem); ok {
					// If this would be the same as source, don't auto-capture;
					// let user explicitly select a different destination.
					if !m.srcSelected || item.title != m.srcItem.title {
						m.dstItem = item
						m.dstSelected = true
					}
				}
			}
		}
	}
}

// AnalyzeTab holds the state for the Analyze tab: a file picker for selecting
// the flow source path (file or directory) and a scrollable form of all
// analyze options (CLI flags + config keys). All fields are value types so the
// tab can be stored in and updated by reassignment on the parent Model.
type AnalyzeTab struct {
	picker          filepicker.Model
	form            Form
	pickerFocused   bool
	pickerCursorPos int           // synthetic cursor index for virtual ".." entry
	dirEntries      []os.DirEntry // mirror of sorted picker listing (dirs first, then files)
}

// Model is the core Bubble Tea model for the TUI simulation.
type Model struct {
	width     int
	height    int
	objects   SelectableObjects
	policyDir string
	policies  []simulate.LoadedPolicy // loaded policies for evaluation

	srcList   list.Model
	dstList   list.Model
	focusList int

	srcSelected bool
	dstSelected bool
	srcItem     selectableItem
	dstItem     selectableItem

	srcListInit bool
	dstListInit bool

	result   *ResultData
	err      error
	quitting bool

	version string
	// Tab navigation
	activeTab  Tab
	activeArea Area
	configPath string

	// Analyze tab state (file picker + options form)
	analyzeTab AnalyzeTab

	// Analyze tab report multi-select
	analyzeReports AnalyzeReports

	// Analyze tab Run button (rendered in Options column, matching Live tab)
	analyzeRunButton RunButton

	// Live tab UI state (source selector + conditional input)
	liveTab LiveTab

	// Live tab run state: set true while the live pipeline is streaming;
	// liveOutput accumulates captured output until the stream ends.
	liveRunning bool
	liveOutput  string

	// Analyze tab run state: set true while the analyze pipeline is running;
	// analyzeOutput stores the pipeline output after completion.
	analyzeRunning bool
	analyzeOutput  string

	liveRunner    LiveRunner
	analyzeRunner AnalyzeRunner
	policyLoader  PolicyLoader

	// Overwrite confirmation dialog state. Set by the CLI layer (which does the
	// directory check — no I/O in the TUI). While showOverwrite is true, Update
	// only accepts the confirmation keys; overwriteConfirmed records the choice.
	showOverwrite      bool
	overwritePath      string
	overwriteConfirmed bool

	// Focus management
	focusField_  int // current focusable field (see inputs.go constants)
	focusStack   []int
	focusDepth   int
	statusMsg    string
	statusFrames int
	statusTimer  tea.Cmd

	// Help dialog state (shown on ?/F1 from any focus state)
	showHelp bool

	// Simulate tab policy-directory file picker (no I/O).
	policyDirPicker filepicker.Model
	policyDirPicked bool
	pickerCursorPos int // synthetic cursor index for virtual ".." entry

	// Input fields
	portInput      textinput.Model
	protoInput     textinput.Model
	l7NameInput    textinput.Model
	l7PatternInput textinput.Model

	// Bottom output pane (shared across all tabs): a scrollable viewport that
	// shows the current tab's output, plus a non-editable CLI preview line.
	outputViewport viewport.Model
	outputFocused  bool
}

// Compile-time check: Model implements tea.Model.
var _ tea.Model = Model{}

// Init initializes the model. Returns nil (no initial command) unless the
// Analyze tab's file picker has been initialized, in which case its directory
// read command is returned so the picker populates.
func (m Model) Init() tea.Cmd {
	if m.activeTab == TabAnalyze && m.analyzeTab.picker.CurrentDirectory != "" {
		return m.analyzeTab.picker.Init()
	}
	if m.activeTab == TabSimulate && !m.policyDirPicked && m.policyDirPicker.CurrentDirectory != "" {
		return m.policyDirPicker.Init()
	}
	return nil
}

// Update processes messages and returns the updated model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	// Keep the persistent viewport's content in sync BEFORE key handling:
	// renderBottomPane runs on a value copy, so without this sync the stored
	// viewport never receives content and scroll keys have nothing to move.
	m.outputViewport.Width = max(m.width, 1)
	m.outputViewport.Height = m.bottomViewportHeight()
	m.outputViewport.SetContent(m.bottomOutputContent())
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.outputViewport.Width = max(m.width, 1)
		m.outputViewport.Height = m.bottomViewportHeight()
		if m.srcListInit || m.dstListInit {
			listWidth := m.width / 2
			width := listWidth
			if width < 20 {
				width = 20
			}
			maxItems := max(len(m.srcList.Items()), len(m.dstList.Items()))
			listHeight := maxItems + 3
			if listHeight < 4 {
				listHeight = 4
			}
			if listHeight > 12 {
				listHeight = 12
			}
			if m.srcListInit {
				m.srcList.SetSize(width, listHeight)
			}
			if m.dstListInit {
				m.dstList.SetSize(width, listHeight)
			}
		}
		return m, nil

	case evalDoneMsg:
		if msg.err != nil {
			m.err = msg.err
			m.result = nil
		} else {
			m.result = msg.result
			m.err = nil
		}
		return m, nil

	case liveDoneMsg:
		m.liveRunning = false
		if msg.err != nil {
			m.liveOutput = fmt.Sprintf("Error: %v\n%s", msg.err, msg.output)
		} else {
			m.liveOutput = msg.output
		}
		return m, nil

	case LiveRunMsg:
		m.liveRunning = true
		m.liveOutput = ""
		return m, m.handleLiveRun()

	case analyzeDoneMsg:
		m.analyzeRunning = false
		if msg.err != nil {
			m.analyzeOutput = fmt.Sprintf("Error: %v\n%s", msg.err, msg.output)
		} else {
			m.analyzeOutput = msg.output
		}
		return m, nil

	case policyLoadedMsg:
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.InitModel(msg.objects, msg.policyDir, msg.policies)
			m.policyDirPicked = true
			m.activeArea = AreaSimSrc
			return m, m.syncAreaFocus()
		}
		return m, nil

	case AnalyzeRunMsg:
		m.analyzeRunning = true
		m.analyzeOutput = ""
		return m, m.handleAnalyzeRun()

	case tea.KeyMsg:
		// Overwrite confirmation dialog takes priority over all other input,
		// including the help dialog. It is a non-blocking state machine: while
		// showOverwrite is true we only accept the confirmation keys and never
		// perform I/O or block the event loop (the directory check is done by
		// the CLI layer before launching the program).
		if m.showOverwrite {
			switch msg.String() {
			case "y", "Y", "enter":
				m.showOverwrite = false
				m.overwriteConfirmed = true
			case "n", "N", "esc":
				m.showOverwrite = false
				m.overwriteConfirmed = false
			case "q", "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}
		// Help dialog takes priority over all other key handling, including
		// when a text input is focused. Esc or q closes it; ?/F1 also toggles
		// it closed so the same keys that open it dismiss it.
		if m.showHelp {
			switch msg.String() {
			case "esc", "q", "?", "f1":
				m.showHelp = false
				return m, nil
			}
			return m, nil
		}
		// Open help from any focus state, before delegating to focused inputs.
		switch msg.String() {
		case "?", "f1":
			m.showHelp = true
			return m, nil
		}
		// Quit on ctrl+c always; quit on q only when not typing in a text
		// input so that q can be entered into the field.
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "q":
			if !m.isAnyEditableFocused() {
				m.quitting = true
				return m, tea.Quit
			}
		}
		// Tab/Shift+Tab always switch areas (by design)
		switch msg.String() {
		case "tab":
			m.cycleArea(1)
			return m, m.syncAreaFocus()
		case "shift+tab":
			m.cycleArea(-1)
			return m, m.syncAreaFocus()
		}
		// Digit keys and left/right switch tabs, but NOT when any text input
		// is focused (so digits can be typed and left/right move the cursor).
		if !m.isAnyEditableFocused() {
			switch msg.String() {
			case "1":
				m.activeTab = TabAnalyze
				m.activeArea = AreaAnalyzePicker
				return m, m.syncAreaFocus()
			case "2":
				m.activeTab = TabLive
				m.activeArea = AreaLiveSelector
				return m, m.syncAreaFocus()
			case "3":
				m.activeTab = TabSimulate
				m.activeArea = AreaSimPolicyDir
				return m, m.syncAreaFocus()
			case "left":
				m.cycleTab(-1)
				m.activeArea = areaForTab(m.activeTab)
				return m, m.syncAreaFocus()
			case "right":
				m.cycleTab(1)
				m.activeArea = areaForTab(m.activeTab)
				return m, m.syncAreaFocus()
			}
		}

		// Bottom output pane: ctrl+o toggles focus. When focused, scroll keys
		// drive the viewport; other keys are swallowed except tab navigation and
		// quit, which fall through to the existing handlers.
		if msg.String() == "ctrl+o" {
			m.outputFocused = !m.outputFocused
			return m, nil
		}
		if m.outputFocused {
			switch msg.String() {
			case "up", "down", "pgup", "pgdown", "k", "j":
				vp, vcmd := m.outputViewport.Update(msg)
				m.outputViewport = vp
				return m, vcmd
			case "esc":
				m.outputFocused = false
				return m, nil
			}
			switch msg.String() {
			case "1", "2", "3", "tab", "shift+tab", "left", "right", "q", "ctrl+c":
				// fall through to existing tab/quit handling
			default:
				return m, nil
			}
		}

		if m.activeTab == TabAnalyze {
			return m.updateAnalyze(msg)
		}
		if m.activeTab == TabLive {
			return m.updateLive(msg)
		}

		// Simulate tab routing by area.
		return m.updateSimulate(msg)
	}

	if m.activeTab == TabAnalyze {
		return m.updateAnalyze(msg)
	}

	if m.activeTab == TabLive {
		m.liveTab, cmd = m.liveTab.UpdateWithState(msg, m.liveRunning)
		return m, cmd
	}

	if m.activeTab == TabSimulate {
		if !m.policyDirPicked {
			picker, cmd := m.policyDirPicker.Update(msg)
			m.policyDirPicker = picker
			return m, cmd
		}
	}

	// Delegate to focused text input (not a list).
	m, cmd = m.updateInputs(msg)
	return m, cmd
}

// View returns the TUI view string.
func (m Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	if m.showHelp {
		return m.renderHelp()
	}

	if m.showOverwrite {
		return m.renderOverwriteDialog()
	}

	header := m.renderHeader()

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color("63")).Render(strings.Repeat("─", max(m.width, 1)))

	var body string
	switch m.activeTab {
	case TabSimulate:
		body = m.renderSimulateBody()
	case TabAnalyze:
		body = m.renderAnalyzeBody()
	case TabLive:
		body = m.renderLiveBody()
	}

	bottom := m.renderBottomPane()

	return header + "\n" + sep + "\n" + body + "\n" + sep + "\n" + bottom
}

// renderHeader renders the top bar with the title, version, and tab strip.
func (m Model) renderHeader() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("130")).
		Padding(0, 1)

	title := titleStyle.Render("flowGuarder")

	var versionStr string
	if m.version != "" {
		versionStr = " " + titleStyle.Render("v"+m.version)
	}

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("  │  ")

	activeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	idleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	tabs := []struct {
		tab   Tab
		label string
	}{
		{TabAnalyze, "Analyze"},
		{TabLive, "Live"},
		{TabSimulate, "Simulate"},
	}
	parts := make([]string, 0, len(tabs))
	for _, tt := range tabs {
		if m.activeTab == tt.tab {
			parts = append(parts, activeStyle.Render("["+tt.label+"]"))
		} else {
			parts = append(parts, idleStyle.Render(tt.label))
		}
	}
	tabBar := strings.Join(parts, "  ")

	helpHint := idleStyle.Render("? Help")

	left := title + versionStr + sep + tabBar
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(helpHint)
	if pad < 2 {
		pad = 2
	}
	return left + strings.Repeat(" ", pad) + helpHint
}

// isTextInputFocused reports whether the current focus is on one of the
// editable text input fields (so that typing q should be entered into the
// field rather than triggering a quit).
func (m Model) isTextInputFocused() bool {
	switch m.focusField_ {
	case focusPort, focusProto, focusL7Name, focusL7Pattern:
		return true
	}
	return false
}

// isFormTextInputFocused reports whether a text input field in the Analyze
// form is currently focused (TextField, NumberField, PortListField, or
// expanded YAMLField). When true, up/down keys should cycle form fields
// rather than scroll the viewport.
func (m Model) isFormTextInputFocused() bool {
	return formTextInputFocused(m.analyzeTab.form)
}

// isAnyEditableFocused reports whether ANY editable text input anywhere in
// the UI currently holds focus: Analyze form fields, legacy port/proto/L7
// fields, or the Live Hubble address field. Global typing shortcuts (digit
// tab-switching, q-to-quit) must yield to focused inputs so their characters
// can be entered.
func (m Model) isAnyEditableFocused() bool {
	return m.isFormTextInputFocused() ||
		formTextInputFocused(m.liveTab.form) ||
		m.isTextInputFocused() ||
		m.liveTab.hubbleAddr.Focused()
}

// formTextInputFocused reports whether a text-entry field of the given form
// (TextField, NumberField, PortListField, or an expanded YAMLField) holds
// focus.
func formTextInputFocused(f Form) bool {
	fld := f.FocusedField()
	if fld == nil {
		return false
	}
	switch v := fld.(type) {
	case TextField, NumberField, PortListField:
		return v.Focused()
	case YAMLField:
		return v.Focused() && !v.collapsed
	}
	return false
}

// pushFocus saves the current focus level for escape-to-return.
func (m *Model) pushFocus() {
	if m.focusStack == nil {
		m.focusStack = make([]int, 0, 4)
	}
	m.focusStack = append(m.focusStack, m.focusField_)
	m.focusDepth++
}

// popFocus restores the previous focus level from the stack.
func (m *Model) popFocus() int {
	if m.focusDepth <= 0 || len(m.focusStack) == 0 {
		return focusTabBar
	}
	m.focusDepth--
	idx := len(m.focusStack) - 1
	f := m.focusStack[idx]
	m.focusStack[idx] = 0
	m.focusStack = m.focusStack[:idx]
	return f
}

// setStatus sets a transient status message to be displayed in the
// bottom pane header for the next n frames.
func (m *Model) setStatus(msg string, frames int) {
	m.statusMsg = msg
	m.statusFrames = frames
	if m.statusTimer != nil {
		m.statusTimer()
	}
}

// focusDescription returns a per-field description string for the currently
// focused field. It handles all three tabs.
func (m Model) focusDescription() string {
	switch m.activeTab {
	case TabAnalyze:
		switch m.activeArea {
		case AreaAnalyzePicker:
			return m.analyzeTab.picker.Path + " — select flow source (file or directory)"
		case AreaAnalyzeForm:
			if f := m.analyzeTab.form.FocusedField(); f != nil {
				return f.Description()
			}
			return "Analyze: edit options · ctrl+o: focus output"
		case AreaAnalyzeReports:
			return "Analyze: select reports & run"
		}
	case TabLive:
		return "Live: configure source"
	case TabSimulate:
		if !m.policyDirPicked {
			return "Select policy directory"
		}
		switch m.activeArea {
		case AreaSimPolicyDir:
			return "Select policy directory"
		case AreaSimSrc:
			return "Select source workload/entity/CIDR"
		case AreaSimDst:
			return "Select destination workload/entity/CIDR"
		case AreaSimInputs:
			return "Set traffic parameters (port, protocol, L7)"
		case AreaSimEval:
			return "Evaluate traffic against loaded policies"
		}
	}
	return "ctrl+o: focus output"
}

// renderHelp renders the keyboard-shortcuts help dialog as a centered,
// K8s-blue (ANSI 63) bordered box. It is shown as an inline replacement of the
// main view while m.showHelp is true.
func (m Model) renderHelp() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("63")).
		Render("Keyboard Shortcuts")

	lines := []string{
		"1/2/3        Switch tabs (Analyze/Live/Simulate)",
		"←/→          Switch tabs (wrapping)",
		"Tab          Next area within tab",
		"Shift+Tab    Previous area within tab",
		"↑/↓ or j/k   Navigate fields within area",
		"Enter        Select / Toggle / Run",
		"Space        Toggle checkbox",
		"Esc          Back / Close dialog",
		"?/F1         Show this help",
		"q/Ctrl+C     Quit",
	}

	body := title + "\n" + strings.Repeat("─", 17) + "\n" + strings.Join(lines, "\n")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 2).
		Render(body)

	if m.width == 0 || m.height == 0 {
		return box
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// renderOverwriteDialog renders the output-directory overwrite confirmation as a
// centered, K8s-blue (ANSI 63) bordered box. It replaces the main view while
// m.showOverwrite is true. No I/O is performed here — the directory check is
// done by the CLI layer, which sets showOverwrite and overwritePath.
func (m Model) renderOverwriteDialog() string {
	titleText := "Confirm Overwrite"
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("63")).
		Render(titleText)

	prompt := fmt.Sprintf("Directory %s already exists. Overwrite? [y/N]", m.overwritePath)

	body := title + "\n" + strings.Repeat("─", len(titleText)) + "\n" + prompt

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 2).
		Render(body)

	if m.width == 0 || m.height == 0 {
		return box
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// renderSimulateBody renders the Simulate tab body (policy-directory file
// picker, source/destination lists, traffic inputs, and the result pane).
func (m Model) renderSimulateBody() string {
	var b strings.Builder

	// Calculate body height accounting for bottom viewport (matching Analyze/Live).
	// Total view = header(1) + sep(1) + body + sep(1) + bottom
	// bottom = bottomHeader(1) + viewport(bottomViewportHeight) + cliPreview(1)
	// = bottomViewportHeight + 3
	// So: 1 + 1 + bodyH + 1 + (bottomViewportHeight + 3) = m.height
	// bodyH = m.height - 6 - bottomViewportHeight
	// Analyze/Live naturally render bodyH + 1 lines due to column layout,
	// so we target bodyH + 1 to match their bottom pane position.
	bodyH := m.height - 6 - m.bottomViewportHeight()
	if bodyH < 5 {
		bodyH = 5
	}

	// Policy-directory file picker is shown until a directory has been selected.
	if !m.policyDirPicked {
		b.WriteString(sectionTitle(m.focusField_ == focusPolicyDir, "Select policy directory:"))
		b.WriteString("\n")
		dir := m.policyDirPicker.CurrentDirectory
		if dir == "" {
			dir = "(none selected)"
		}
		b.WriteString("  Policy dir: ")
		b.WriteString(dir)
		b.WriteString("\n")
		// Render ".." entry: when cursor is at position 0, replace the
		// picker's first line with ".." to avoid two simultaneous ">"
		// indicators (the picker's own cursor on file[0] + our synthetic line).
		pickerView := safeFilePickerView(m.policyDirPicker)
		if m.policyDirPicker.CurrentDirectory != "/" && m.policyDirPicker.CurrentDirectory != "." && m.pickerCursorPos == 0 {
			lines := strings.SplitN(pickerView, "\n", 2)
			if len(lines) > 1 {
				b.WriteString("> ..\n")
				line0 := stripFilePickerCursor(lines[0])
				b.WriteString("  " + line0 + "\n")
				b.WriteString(lines[1])
			} else {
				b.WriteString("> ..\n")
			}
		} else if m.policyDirPicker.CurrentDirectory != "/" && m.policyDirPicker.CurrentDirectory != "." {
			// ".." is not focused — render it as plain text above the picker.
			b.WriteString("  ..\n")
			b.WriteString(pickerView)
		} else {
			b.WriteString(pickerView)
		}
		b.WriteString("\n")

		// Pad picker view to fill body height so bottom pane stays at terminal bottom.
		bodyLines := strings.Split(b.String(), "\n")
		if len(bodyLines) < bodyH {
			padding := strings.Repeat("\n", bodyH-len(bodyLines))
			b.WriteString(padding)
		}
		return b.String()
	}

	if m.policyDirPicked && !m.srcListInit {
		b.WriteString("\n  No policies loaded.\n")
		b.WriteString("  Use 'flowguarder simulate --policies <dir> --tui' for interactive simulation.\n")
		b.WriteString("  Or run Analyze/Live first to generate policies.\n")

		// Pad to body height.
		bodyLines := strings.Split(b.String(), "\n")
		if len(bodyLines) < bodyH {
			padding := strings.Repeat("\n", bodyH-len(bodyLines))
			b.WriteString(padding)
		}
		return b.String()
	}

	if m.policyDirPicked {
		listWidth := m.width / 2

		// listH = bodyH - 2 makes total body = listH + 9 = bodyH + 7 (matches Analyze left column).
		listH := bodyH - 2
		if listH < 4 {
			listH = 4
		}
		if listH > 20 {
			listH = 20
		}
		if m.srcListInit {
			m.srcList.SetSize(listWidth, listH)
		}
		if m.dstListInit {
			m.dstList.SetSize(listWidth, listH)
		}

		var srcView, dstView string
		if m.srcListInit {
			if m.focusField_ == focusSrc {
				m.srcList.Styles.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
			} else {
				m.srcList.Styles.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("241"))
			}
			srcView = m.srcList.View()
		}
		if m.dstListInit {
			if m.focusField_ == focusDst {
				m.dstList.Styles.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
			} else {
				m.dstList.Styles.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("241"))
			}
			dstView = m.dstList.View()
		}

		top := lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(listWidth).Render(srcView),
			lipgloss.NewStyle().Width(listWidth).Render(dstView),
		)

		b.WriteString(top)
		b.WriteString("\n")
		b.WriteString(m.inputView())

		// Pad to body height so bottom pane stays at terminal bottom.
		bodyLines := strings.Split(b.String(), "\n")
		if len(bodyLines) < bodyH {
			padding := strings.Repeat("\n", bodyH-len(bodyLines))
			b.WriteString(padding)
		}
	}
	return b.String()
}

func (m Model) renderLiveBody() string {
	return m.liveTab.ViewWithState(m.liveRunning, m.width, m.height)
}

func (m Model) renderAnalyzeReports() string {
	return m.analyzeReports.View()
}

// InitModel initializes the list state for the given selectable objects.
func (m *Model) InitModel(objects SelectableObjects, policyDir string, policies []simulate.LoadedPolicy) {
	m.objects = objects
	m.policyDir = policyDir
	m.policies = policies
	m.srcList = newList(buildSrcItems(objects), "Source Pickers")
	m.dstList = newList(buildDstItems(objects), "Destination Pickers")
	// Set initial list size so they render properly before the first
	// WindowSizeMsg.  newList() creates lists with width=0; without this
	// the first render after policyLoadedMsg shows invisible lists.
	if m.width > 0 {
		listWidth := m.width / 2
		if listWidth < 20 {
			listWidth = 20
		}
		maxItems := max(len(m.srcList.Items()), len(m.dstList.Items()))
		listHeight := maxItems + 3
		if listHeight < 4 {
			listHeight = 4
		}
		if listHeight > 12 {
			listHeight = 12
		}
		m.srcList.SetSize(listWidth, listHeight)
		m.dstList.SetSize(listWidth, listHeight)
	}
	m.focusList = 0
	m.initInputs()
	m.initSimulatePicker()
	m.srcListInit = true
	m.dstListInit = true
	if len(m.srcList.Items()) > 0 {
		m.srcList.Select(0)
		if it, ok := m.srcList.Items()[0].(selectableItem); ok {
			m.srcItem = it
			m.srcSelected = true
		}
	}
	if len(m.dstList.Items()) > 0 {
		m.dstList.Select(0)
		if it, ok := m.dstList.Items()[0].(selectableItem); ok {
			m.dstItem = it
			m.dstSelected = true
		}
	}
	// When a policy directory is already known (e.g. `simulate --tui
	// --policies`), skip the picker and focus the source list directly.
	// Otherwise the picker is the first focusable element.
	if m.policyDir != "" {
		m.policyDirPicked = true
		m.focusField_ = focusSrc
	} else {
		m.policyDirPicked = false
		m.focusField_ = focusPolicyDir
	}
}

// initSimulatePicker initializes the policy-directory file picker. It performs
// no I/O: the picker only navigates the local filesystem view; policy loading
// is done by the CLI layer before Run/RunUnified is invoked. Directories are
// selectable (DirAllowed); files are not, so only a policy directory can be
// confirmed. No extension filter is applied (AllowedTypes = nil).
func (m *Model) initSimulatePicker() {
	picker := filepicker.New()
	picker.DirAllowed = true
	picker.FileAllowed = false
	picker.AllowedTypes = nil
	picker.AutoHeight = false
	picker.SetHeight(12)
	if m.policyDir != "" {
		picker.CurrentDirectory = m.policyDir
		picker.Path = m.policyDir
	} else {
		picker.CurrentDirectory = "."
		picker.Path = "."
	}
	// Initialize picker synchronously so its directory listing is populated
	// before the first View() call. Without this the picker renders empty.
	if cmd := picker.Init(); cmd != nil {
		msg := cmd()
		picker, _ = picker.Update(msg)
	}
	m.policyDirPicker = picker
}

// Run creates a new Model with the given selectable objects and runs the Bubble Tea program
// in alternate screen mode (full terminal).
func Run(objects SelectableObjects, policyDir string, policies []simulate.LoadedPolicy) error {
	m := Model{
		focusList: 0,
		activeTab: TabSimulate,
	}
	m.outputViewport = viewport.New(max(m.width, 80), 5)
	m.InitModel(objects, policyDir, policies)

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// UnifiedOpts holds optional runner functions injected by the CLI layer.
type UnifiedOpts struct {
	AnalyzeRunner AnalyzeRunner
	LiveRunner    LiveRunner
	PolicyLoader  PolicyLoader
}

// RunUnified launches the unified TUI with the given version string. The Analyze
// tab is shown first; the Simulate tab (and its form) is reachable via the tab
// strip (1/2/3 or Tab/Shift+Tab).
func RunUnified(version string, configPath string, opts ...UnifiedOpts) error {
	m := Model{
		version:    version,
		activeTab:  TabAnalyze,
		configPath: configPath,
	}
	m.outputViewport = viewport.New(80, 5)
	m.analyzeTab = NewAnalyzeTab()
	m.analyzeReports = NewAnalyzeReports("Reports", "Select report sections to generate").Focus().(AnalyzeReports)
	m.initInputs()
	m.initSimulatePicker()
	m.liveTab = NewLiveTab()
	m.analyzeRunButton = NewRunButton("Run")
	if len(opts) > 0 {
		m.analyzeRunner = opts[0].AnalyzeRunner
		m.liveRunner = opts[0].LiveRunner
		m.policyLoader = opts[0].PolicyLoader
	}
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil {
			m.analyzeTab.form.SetConfig(cfg)
		}
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// cycleTab moves the active tab forward (dir=1) or backward (dir=-1), wrapping
// around the three-tab range.
func (m *Model) cycleTab(dir int) {
	t := int(m.activeTab) + dir
	if t < int(TabAnalyze) {
		t = int(TabSimulate)
	} else if t > int(TabSimulate) {
		t = int(TabAnalyze)
	}
	m.activeTab = Tab(t)
}

// syncAreaFocus updates focus state to match the current activeArea. Called
// after area transitions to ensure the correct UI element shows focus.
// Returns a tea.Cmd to initialize the policy-directory picker when switching
// to the Simulate tab's picker area for the first time.
func (m *Model) syncAreaFocus() tea.Cmd {
	switch m.activeTab {
	case TabAnalyze:
		switch m.activeArea {
		case AreaAnalyzePicker:
			m.analyzeTab.pickerFocused = true
			m.analyzeTab.form = blurForm(m.analyzeTab.form)
			m.analyzeReports = m.analyzeReports.Blur().(AnalyzeReports)
		case AreaAnalyzeForm:
			m.analyzeTab.pickerFocused = false
			m.analyzeReports = m.analyzeReports.Blur().(AnalyzeReports)
			if len(m.analyzeTab.form.fields) > 0 {
				if m.analyzeTab.form.FocusedIndex() < 0 {
					m.analyzeTab.form = m.analyzeTab.form.SetFocus(0)
				}
			}
		case AreaAnalyzeReports:
			m.analyzeTab.pickerFocused = false
			m.analyzeTab.form = blurForm(m.analyzeTab.form)
			m.analyzeReports = m.analyzeReports.Focus().(AnalyzeReports)
		case AreaAnalyzeRun:
			m.analyzeTab.pickerFocused = false
			m.analyzeTab.form = blurForm(m.analyzeTab.form)
			m.analyzeReports = m.analyzeReports.Blur().(AnalyzeReports)
		}
	case TabSimulate:
		switch m.activeArea {
		case AreaSimPolicyDir:
			m.setFocus(focusPolicyDir)
			return m.policyDirPicker.Init()
		case AreaSimSrc:
			m.setFocus(focusSrc)
			// Auto-capture currently highlighted source item when entering this area
			if m.srcListInit && len(m.srcList.Items()) > 0 {
				if idx := m.srcList.Index(); idx >= 0 {
					items := m.srcList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							m.srcItem = item
							m.srcSelected = true
						}
					}
				}
			}
		case AreaSimDst:
			m.setFocus(focusDst)
			// Auto-capture currently highlighted destination item when entering this area,
			// but avoid capturing the same item as source (both lists start at index 0).
			if m.dstListInit && len(m.dstList.Items()) > 0 {
				if idx := m.dstList.Index(); idx >= 0 {
					items := m.dstList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							// If this would be the same as source, don't auto-capture;
							// let user explicitly select a different destination.
							if !m.srcSelected || item.title != m.srcItem.title {
								m.dstItem = item
								m.dstSelected = true
							}
						}
					}
				}
			}
		case AreaSimInputs:
			m.setFocus(focusPort)
		case AreaSimEval:
			m.setFocus(focusEval)
		}
	case TabLive:
		// Blur everything first
		m.liveTab.selector = m.liveTab.selector.Blur().(LiveSourceSelector)
		m.liveTab.hubbleAddr = m.liveTab.hubbleAddr.Blur().(TextField)
		m.liveTab.Reports = m.liveTab.Reports.Blur().(AnalyzeReports)
		switch m.activeArea {
		case AreaLiveSelector:
			m.liveTab.focusIndex = 0
			m.liveTab.selector = m.liveTab.selector.Focus().(LiveSourceSelector)
		case AreaLiveReports:
			m.liveTab.focusIndex = -1
			m.liveTab.Reports = m.liveTab.Reports.Focus().(AnalyzeReports)
		case AreaLiveInput:
			m.liveTab.focusIndex = 1
			if m.liveTab.selector.source == LiveSourceHubble {
				m.liveTab.hubbleAddr = m.liveTab.hubbleAddr.Focus().(TextField)
			}
		case AreaLiveForm:
			m.liveTab.focusIndex = 2
			if len(m.liveTab.form.fields) > 0 {
				if m.liveTab.form.FocusedIndex() < 0 {
					m.liveTab.form = m.liveTab.form.SetFocus(0)
				}
			}
		case AreaLiveButton:
			m.liveTab.focusIndex = 3
			m.liveTab.form = blurForm(m.liveTab.form)
		}
	}
	return nil
}

func (m Model) updateLive(msg tea.Msg) (Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "enter":
			if m.activeArea == AreaLiveButton && !m.liveRunning {
				return m, func() tea.Msg { return LiveRunMsg{} }
			}
		case "up", "k":
			if m.activeArea == AreaLiveButton {
				m.activeArea = AreaLiveForm
				return m, m.syncAreaFocus()
			}
			// Arrow up from Hubble input returns to the selector.
			if m.activeArea == AreaLiveInput && m.liveTab.selector.source == LiveSourceHubble {
				m.activeArea = AreaLiveSelector
				return m, m.syncAreaFocus()
			}
		case "down", "j":
			if m.activeArea == AreaLiveSelector && m.liveTab.selector.cursor >= 1 {
				m.activeArea = AreaLiveInput
				m.liveTab.selector = m.liveTab.selector.Blur().(LiveSourceSelector)
				if m.liveTab.selector.source == LiveSourceHubble {
					m.liveTab.hubbleAddr = m.liveTab.hubbleAddr.Focus().(TextField)
				}
				return m, m.syncAreaFocus()
			}
			if m.activeArea == AreaLiveInput && m.liveTab.selector.source == LiveSourceHubble {
				m.activeArea = AreaLiveReports
				return m, m.syncAreaFocus()
			}
		}
	}
	// Reports section holds focus: arrows/space drive the toggle group
	// itself (mirrors the Analyze reports routing); Tab cycles areas via the
	// global handler, esc blurs into the options form.
	if m.activeArea == AreaLiveReports {
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "esc" {
			m.liveTab.Reports = m.liveTab.Reports.Blur().(AnalyzeReports)
			m.activeArea = AreaLiveForm
			return m, m.syncAreaFocus()
		}
		updated, c := m.liveTab.Reports.Update(msg)
		m.liveTab.Reports = updated.(AnalyzeReports)
		return m, c
	}
	var cmd tea.Cmd
	m.liveTab, cmd = m.liveTab.UpdateWithState(msg, m.liveRunning)

	// Sync activeArea from LiveTab's internal focusIndex in case it was
	// changed by UpdateWithState / Update (e.g. "down" from Hubble text
	// input sets focusIndex=2 inside LiveTab.Update).
	switch m.liveTab.focusIndex {
	case -1:
		// Reports area owns focus; keep activeArea as-is.
	case 0:
		m.activeArea = AreaLiveSelector
	case 1:
		m.activeArea = AreaLiveInput
	case 2:
		m.activeArea = AreaLiveForm
	case 3:
		m.activeArea = AreaLiveButton
	}
	return m, cmd
}

func (m Model) updateSimulate(msg tea.Msg) (Model, tea.Cmd) {
	switch m.activeArea {
	case AreaSimPolicyDir:
		if !m.policyDirPicked {
			// When on the synthetic ".." entry, handle navigation ourselves and
			// prevent the Bubbles picker from moving its internal cursor. This
			// keeps our synthetic cursor in sync: cursorPos==0 → "..", picker
			// cursor at 0; cursorPos==1 → first file, picker cursor still at 0.
			if m.pickerCursorPos == 0 {
				if key, ok := msg.(tea.KeyMsg); ok {
					switch key.String() {
					case "down", "j", "ctrl+n":
						m.pickerCursorPos++
						return m, nil
					case "up", "k", "ctrl+p", "pgup", "pgdown", "g", "K":
						return m, nil
					}
				}
			}

			if key, ok := msg.(tea.KeyMsg); ok {
				switch key.String() {
				case "up", "k", "ctrl+p":
					if m.pickerCursorPos > 0 {
						m.pickerCursorPos--
					}
				case "down", "j", "ctrl+n":
					m.pickerCursorPos++
				case "g":
					m.pickerCursorPos = 0
				case "pgup", "K":
					m.pickerCursorPos = 0
				case "enter":
					if m.pickerCursorPos == 0 {
						// ".." entry: navigate to parent directory.
						parent := filepath.Dir(m.policyDirPicker.CurrentDirectory)
						if parent != m.policyDirPicker.CurrentDirectory {
							m.policyDirPicker.CurrentDirectory = parent
							m.policyDirPicker.Path = ""
							m.pickerCursorPos = 0
							m.policyDir = parent
							return m, m.policyDirPicker.Init()
						}
					}
				}
			}

			oldDir := m.policyDirPicker.CurrentDirectory
			picker, cmd := m.policyDirPicker.Update(msg)
			m.policyDirPicker = picker
			m.policyDir = picker.CurrentDirectory
			if picker.CurrentDirectory != oldDir {
				m.pickerCursorPos = 0
			}
			// Only mark as picked when user explicitly selects a directory
			// (Enter on dir). DidSelectFile returns true for directories
			// when DirAllowed=true.
			if didSelect, path := picker.DidSelectFile(msg); didSelect {
				if info, err := os.Stat(path); err == nil && info.IsDir() {
					if m.policyLoader != nil {
						m.policyDirPicked = true
						dir := picker.CurrentDirectory
						return m, func() tea.Msg {
							policies, objects, err := m.policyLoader(dir)
							return policyLoadedMsg{
								objects:   objects,
								policyDir: dir,
								policies:  policies,
								err:       err,
							}
						}
					}
				}
			}
			return m, cmd
		}
	case AreaSimSrc:
		if m.srcListInit {
			if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
				if idx := m.srcList.Index(); idx >= 0 {
					items := m.srcList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							m.srcItem = item
							m.srcSelected = true
						}
					}
				}
				m.activeArea = AreaSimDst
				return m, m.syncAreaFocus()
			}
			srcList, cmd := m.srcList.Update(msg)
			m.srcList = srcList
			return m, cmd
		}
	case AreaSimDst:
		if m.dstListInit {
			if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
				if idx := m.dstList.Index(); idx >= 0 {
					items := m.dstList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							m.dstItem = item
							m.dstSelected = true
						}
					}
				}
				m.activeArea = AreaSimInputs
				return m, m.syncAreaFocus()
			}
			dstList, cmd := m.dstList.Update(msg)
			m.dstList = dstList
			return m, cmd
		}
	case AreaSimInputs:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "up", "k":
				if m.focusField_ > focusPort {
					m.setFocus(m.focusField_ - 1)
				}
				return m, nil
			case "down", "j":
				if m.focusField_ < focusL7Pattern {
					m.setFocus(m.focusField_ + 1)
				} else {
					m.activeArea = AreaSimEval
					return m, m.syncAreaFocus()
				}
				return m, nil
			}
		}
		m, cmd := m.updateInputs(msg)
		return m, cmd
	case AreaSimEval:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "enter":
				return m, m.evaluate()
			case "up", "k", "esc":
				m.activeArea = AreaSimInputs
				m.setFocus(focusL7Pattern)
				return m, m.syncAreaFocus()
			case "down", "j":
				// Wrap to source list (or stay)
				m.activeArea = AreaSimSrc
				return m, m.syncAreaFocus()
			}
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Evaluation logic
// ---------------------------------------------------------------------------

// evalDoneMsg is the message sent when policy evaluation completes.
type evalDoneMsg struct {
	result *ResultData
	err    error
}

// evaluate returns a tea.Cmd that evaluates the selected source/destination
// against the loaded policies with the configured traffic parameters.
func (m Model) evaluate() tea.Cmd {
	return func() tea.Msg {
		src, err := m.itemToEndpoint(m.srcItem)
		if err != nil {
			return evalDoneMsg{err: fmt.Errorf("source: %w", err)}
		}
		dst, err := m.itemToEndpoint(m.dstItem)
		if err != nil {
			return evalDoneMsg{err: fmt.Errorf("destination: %w", err)}
		}

		protocol := strings.ToUpper(strings.TrimSpace(m.protoInput.Value()))
		if protocol == "" {
			protocol = "TCP"
		}
		port := 0
		if v := strings.TrimSpace(m.portInput.Value()); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
		traffic := simulate.Traffic{
			Port:     port,
			Protocol: protocol,
		}
		l7Name := strings.TrimSpace(m.l7NameInput.Value())
		l7Pattern := strings.TrimSpace(m.l7PatternInput.Value())

		var l7Traffic *simulate.Traffic
		if l7Name != "" || l7Pattern != "" {
			l7Traffic = &simulate.Traffic{L7Name: l7Name, L7Pattern: l7Pattern}
		}

		npResult := simulate.EvaluateNetworkPolicy(src, dst, traffic, m.policies)
		cnpResult := simulate.EvaluateCiliumNetworkPolicy(src, dst, traffic, m.policies, l7Traffic)
		combined := combineVerdicts(npResult, cnpResult)

		return evalDoneMsg{result: &ResultData{
			Ingress:       string(combined.Ingress),
			Egress:        string(combined.Egress),
			MatchingFiles: combined.MatchingFiles,
		}}
	}
}

// itemToEndpoint converts a selected list item into a simulate.Endpoint.
func (m Model) itemToEndpoint(item selectableItem) (simulate.Endpoint, error) {
	var ep simulate.Endpoint
	title := item.title

	// Entity: title starts with "entity:"
	if strings.HasPrefix(title, "entity:") {
		ep.Entity = strings.TrimPrefix(title, "entity:")
		return ep, nil
	}

	// CIDR: title looks like a CIDR (contains "/" with numeric second part)
	if isCIDRPath(title) {
		ep.IP = title
		return ep, nil
	}

	// namespace/name workload (the common case)
	parts := strings.SplitN(title, "/", 2)
	if len(parts) == 2 {
		ep.Namespace = parts[0]
		ep.Labels = map[string]string{"app": parts[1]}
		return ep, nil
	}

	return ep, fmt.Errorf("cannot convert %q to endpoint", title)
}

// isCIDRPath checks if title looks like a literal IP or CIDR.
func isCIDRPath(title string) bool {
	// "Custom IP/CIDR" is not a CIDR
	if title == "Custom IP/CIDR" {
		return false
	}
	parts := strings.SplitN(title, "/", 2)
	if len(parts) != 2 {
		return false
	}
	// Must look like an IP: contains "." (IPv4) or ":" (IPv6)
	return strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")
}

// ---------------------------------------------------------------------------
// Verdict helpers
// ---------------------------------------------------------------------------

func combineVerdicts(np, cnp simulate.Result) simulate.Result {
	return simulate.Result{
		Ingress:       combineSingleVerdict(np.Ingress, cnp.Ingress),
		Egress:        combineSingleVerdict(np.Egress, cnp.Egress),
		MatchingFiles: dedupSorted(append(np.MatchingFiles, cnp.MatchingFiles...)),
	}
}

func combineSingleVerdict(a, b simulate.Verdict) simulate.Verdict {
	if a == simulate.VerdictAllow || b == simulate.VerdictAllow {
		return simulate.VerdictAllow
	}
	if a == simulate.VerdictDeny || b == simulate.VerdictDeny {
		return simulate.VerdictDeny
	}
	return simulate.VerdictUndetermined
}

func dedupSorted(f []string) []string {
	if len(f) == 0 {
		return nil
	}
	sorted := make([]string, 0, len(f))
	seen := make(map[string]struct{}, len(f))
	for _, x := range f {
		if _, ok := seen[x]; !ok {
			seen[x] = struct{}{}
			sorted = append(sorted, x)
		}
	}
	sort.Strings(sorted)
	return sorted
}

// ---------------------------------------------------------------------------
// Bottom output pane (shared across all tabs)
// ---------------------------------------------------------------------------

// bottomViewportHeight returns the number of lines allocated to the scrollable
// output viewport, derived from the terminal height so the pane stays compact.
func (m Model) bottomViewportHeight() int {
	h := 5
	if m.height > 0 {
		avail := m.height - 14 // reserve top header, separators, and body minimum
		if avail > h {
			h = avail / 3
		}
		if h < 3 {
			h = 3
		}
		if h > 12 {
			h = 12
		}
	}
	return h
}

// renderBottomPane renders the shared bottom output area: a header line (focus
// description or status), a scrollable viewport showing the current tab's
// output, and a non-editable CLI preview line.
func (m Model) renderBottomPane() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	m.outputViewport.Width = w
	m.outputViewport.Height = m.bottomViewportHeight()
	m.outputViewport.SetContent(m.bottomOutputContent())

	var b strings.Builder
	b.WriteString(m.renderBottomHeader())
	b.WriteString("\n")
	b.WriteString(m.outputViewport.View())
	b.WriteString("\n")
	b.WriteString(m.renderCLIPreviewLine())
	// Hard-clamp every line to the terminal width: a single overflowing row
	// soft-wraps in the real terminal, growing the painted frame beyond what
	// Bubble Tea declared and corrupting the previous frame (ghost doubles).
	return lipgloss.NewStyle().MaxWidth(w).Render(b.String())
}

// renderBottomHeader renders the bottom-pane header line. When the output
// viewport is focused it shows the scroll hint; otherwise it shows the current
// tab's focus description or status.
func (m Model) renderBottomHeader() string {
	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("63")).
		Padding(0, 1)
	idleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("63"))
	var label string
	var hint string
	if m.outputFocused {
		label = labelStyle.Render("Output ▾")
		hint = "scroll ↑/↓/PgUp/PgDn · ctrl+o: unfocus"
	} else {
		label = idleStyle.Render("Output")
		hint = m.focusStatus()
	}
	return label + " " + hint
}

// focusStatus returns a short status/focus description for the active tab.
func (m Model) focusStatus() string {
	switch m.activeTab {
	case TabAnalyze:
		switch m.activeArea {
		case AreaAnalyzePicker:
			return "Analyze: select flow source · ctrl+o: focus output"
		case AreaAnalyzeForm:
			return "Analyze: edit options · ↑↓ navigate · ctrl+o: focus output"
		case AreaAnalyzeReports:
			return "Analyze: select reports · ↑↓ navigate · enter: toggle"
		case AreaAnalyzeRun:
			return "Analyze: run analysis · enter: run · esc: back"
		}
	case TabLive:
		return "Live: configure source · ctrl+o: focus output"
	case TabSimulate:
		return "Simulate: pick src/dst, set traffic · ctrl+o: focus output"
	}
	return "ctrl+o: focus output"
}

// bottomOutputContent returns the scrollable content for the active tab.
func (m Model) bottomOutputContent() string {
	switch m.activeTab {
	case TabSimulate:
		return m.resultView()
	case TabAnalyze:
		return m.analyzeOutputPreview()
	case TabLive:
		return m.liveOutputPreview()
	}
	return ""
}

func (m Model) analyzeOutputPreview() string {
	if m.analyzeRunning {
		src := m.analyzeTab.Values()["Source"]
		if src == "" {
			src = "<source>"
		}
		return fmt.Sprintf("Running… analyzing %s\n", src)
	}
	if m.analyzeOutput != "" {
		return m.analyzeOutput
	}
	v := m.analyzeTab.Values()
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("Analyze options (preview):\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s = %s\n", k, v[k])
	}
	return b.String()
}

// liveOutputPreview renders the current live configuration for the bottom pane.
func (m Model) liveOutputPreview() string {
	if m.liveRunning {
		switch m.liveTab.Source() {
		case LiveSourceHubble:
			return fmt.Sprintf("Running… streaming from Hubble (%s)\n", m.liveTab.HubbleAddress())
		case LiveSourceCalico:
			return fmt.Sprintf("Running… streaming from Calico (%s)\n", m.liveTab.CalicoFilePath())
		}
		return "Running…\n"
	}
	if m.liveOutput != "" {
		return m.liveOutput
	}
	var b strings.Builder
	b.WriteString("Live options (preview):\n")
	switch m.liveTab.Source() {
	case LiveSourceHubble:
		fmt.Fprintf(&b, "  source = hubble\n  hubble-server = %s\n", m.liveTab.HubbleAddress())
	case LiveSourceCalico:
		fmt.Fprintf(&b, "  source = calico\n  calico-file = %s\n", m.liveTab.CalicoFilePath())
	}
	// Include form options like Analyze does
	v := m.liveTab.form.Values()
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s = %s\n", k, v[k])
	}
	return b.String()
}

// handleLiveRun builds a cobra.Command with the Live tab's form values and
// runs the live pipeline. Output is captured in a buffer and returned via
// liveDoneMsg. SIGINT/SIGTERM are handled through signal.NotifyContext.
func (m Model) handleLiveRun() tea.Cmd {
	return func() tea.Msg {
		if m.liveRunner == nil {
			return liveDoneMsg{err: fmt.Errorf("live runner not configured")}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		var address string
		var source LiveSource
		switch m.liveTab.Source() {
		case LiveSourceHubble:
			address = m.liveTab.HubbleAddress()
			source = LiveSourceHubble
		case LiveSourceCalico:
			address = m.liveTab.CalicoFilePath()
			source = LiveSourceCalico
		}

		liveVals := m.liveTab.form.Values()
		outputDir := liveVals["--output"]
		format := liveVals["--format"]
		policyFormat := liveVals["--policy-format"]
		strict := liveVals["--strict"] == "true"
		defaultDeny := liveVals["--default-deny"] == "true"
		vizLayout := liveVals["--viz-layout"]

		output, err := m.liveRunner(ctx, source, address, outputDir, format, policyFormat, strict, defaultDeny, m.liveTab.Reports.Values(), vizLayout)

		// Write effective config YAML to the output directory on success.
		if err == nil && outputDir != "" {
			if cfgYAML, cfgErr := marshalConfigOutput(liveVals); cfgErr == nil {
				cfgPath := filepath.Join(outputDir, "flowguarder-config.yaml")
				if equalPaths(m.configPath, cfgPath) {
					output += "\nSkipped config save: input and output config paths match\n"
				} else if writeErr := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); writeErr == nil {
					output += fmt.Sprintf("\nEffective config written to %s\n", cfgPath)
				}
			}
		}

		return liveDoneMsg{output: output, err: err}
	}
}

// equalPaths resolves inPath and outPath to absolute paths and returns true
// if they resolve to the same canonical location, or if inPath is empty.
func equalPaths(inPath, outPath string) bool {
	if inPath == "" {
		return false
	}
	absIn, errIn := filepath.Abs(inPath)
	absOut, errOut := filepath.Abs(outPath)
	return errIn == nil && errOut == nil && absIn == absOut
}

func (m Model) handleAnalyzeRun() tea.Cmd {
	return func() tea.Msg {
		if m.analyzeRunner == nil {
			return analyzeDoneMsg{err: fmt.Errorf("analyze runner not configured")}
		}

		v := m.analyzeTab.Values()
		sourcePath := v["Source"]
		outputDir := v["--output"]
		format := v["--format"]
		policyFormat := v["--policy-format"]
		strict := v["--strict"] == "true"
		defaultDeny := v["--default-deny"] == "true"
		cilium := v["--cilium"] == "true"
		reports := m.analyzeReports.Values()
		topN := 10
		if n := v["--top-n"]; n != "" {
			if parsed, err := strconv.Atoi(n); err == nil {
				topN = parsed
			}
		}
		vizLayout := v["--viz-layout"]

		output, err := m.analyzeRunner(sourcePath, outputDir, format, policyFormat, strict, defaultDeny, cilium, reports, topN, vizLayout)

		// Write effective config YAML to the output directory on success.
		if err == nil && outputDir != "" {
			if cfgYAML, cfgErr := marshalConfigOutput(v); cfgErr == nil {
				cfgPath := filepath.Join(outputDir, "flowguarder-config.yaml")
				if writeErr := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); writeErr == nil {
					output += fmt.Sprintf("\nEffective config written to %s\n", cfgPath)
				}
			}
		}

		return analyzeDoneMsg{output: output, err: err}
	}
}

// renderCLIPreviewLine renders the non-editable CLI preview line for the bottom
// pane, showing the equivalent flowguarder command for the current tab.
func (m Model) renderCLIPreviewLine() string {
	prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("$ ")
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color("63")).Render(buildCLIPreview(m))
	return prompt + cmd
}

// buildCLIPreview returns the equivalent flowguarder CLI command for the active
// tab, derived from its form state. It is the single source of truth for the
// bottom-pane CLI preview (no per-tab duplication).
func buildCLIPreview(m Model) string {
	switch m.activeTab {
	case TabAnalyze:
		return buildAnalyzeCLIPreview(m)
	case TabLive:
		return buildLiveCLIPreview(m)
	case TabSimulate:
		return buildSimulateCLIPreview(m)
	}
	return ""
}

// buildAnalyzeCLIPreview builds `flowguarder analyze <source> --output ...`
// from the Analyze tab's form values.
func buildAnalyzeCLIPreview(m Model) string {
	v := m.analyzeTab.Values()
	src := v["Source"]
	if src == "" {
		src = "<source>"
	}
	args := []string{"flowguarder", "analyze", src}
	flags := []string{
		"--output", "--format", "--policy-format", "--strict",
		"--default-deny", "--top-n", "--generate-uncovered",
		"--skip-visualize", "--cilium",
	}
	for _, f := range flags {
		val, ok := v[f]
		if !ok {
			continue
		}
		if isBoolFlag(f) {
			if val == "true" {
				args = append(args, f)
			}
			continue
		}
		if val != "" {
			args = append(args, f, val)
		}
	}
	for _, r := range m.analyzeReports.Values() {
		args = append(args, "--report", r)
	}
	// Deliberately outside the flags loop above: "auto" is the CLI default
	// and must be omitted, which the loop's non-empty check cannot express.
	if vl := v["--viz-layout"]; vl != "" && vl != "auto" {
		args = append(args, "--viz-layout", vl)
	}
	return strings.Join(args, " ")
}

// buildLiveCLIPreview builds `flowguarder live --hubble-server <addr>` or
// `--calico-file <path>` from the Live tab's state.
func buildLiveCLIPreview(m Model) string {
	args := []string{"flowguarder", "live"}
	switch m.liveTab.Source() {
	case LiveSourceHubble:
		addr := m.liveTab.HubbleAddress()
		if addr == "" {
			addr = "<host:port>"
		}
		args = append(args, "--hubble-server", addr)
	case LiveSourceCalico:
		path := m.liveTab.CalicoFilePath()
		if path == "" {
			path = "<path>"
		}
		args = append(args, "--calico-file", path)
	}
	for _, r := range m.liveTab.Reports.Values() {
		args = append(args, "--report", r)
	}
	// Same omit-when-auto contract as buildAnalyzeCLIPreview.
	if vl := m.liveTab.form.Values()["--viz-layout"]; vl != "" && vl != "auto" {
		args = append(args, "--viz-layout", vl)
	}
	return strings.Join(args, " ")
}

// buildSimulateCLIPreview builds `flowguarder simulate --policies <dir> --src
// <src> --dst <dst> --port <port> ...` from the Simulate tab's state.
func buildSimulateCLIPreview(m Model) string {
	dir := m.policyDir
	if dir == "" {
		dir = "<dir>"
	}
	args := []string{"flowguarder", "simulate", "--policies", dir}
	if m.srcSelected {
		args = append(args, "--src", m.srcItem.title)
	}
	if m.dstSelected {
		args = append(args, "--dst", m.dstItem.title)
	}
	if p := strings.TrimSpace(m.portInput.Value()); p != "" {
		args = append(args, "--port", p)
	}
	if proto := strings.TrimSpace(m.protoInput.Value()); proto != "" && proto != "TCP" {
		args = append(args, "--protocol", proto)
	}
	if l7 := strings.TrimSpace(m.l7NameInput.Value()); l7 != "" {
		args = append(args, "--l7-name", l7)
	}
	if l7p := strings.TrimSpace(m.l7PatternInput.Value()); l7p != "" {
		args = append(args, "--l7-pattern", l7p)
	}
	return strings.Join(args, " ")
}

// isBoolFlag reports whether the analyze CLI flag is a boolean toggle.
func isBoolFlag(f string) bool {
	switch f {
	case "--strict", "--default-deny", "--generate-uncovered", "--skip-visualize", "--cilium":
		return true
	}
	return false
}

type configOutput struct {
	ClusterCIDRs               []string                   `yaml:"cluster_cidrs,omitempty"`
	APIServerCIDRs             []string                   `yaml:"apiserver_cidrs,omitempty"`
	ExcludedNamespaces         []string                   `yaml:"excluded_namespaces,omitempty"`
	KubeDNSPorts               []config.PortSpec          `yaml:"kube_dns_ports,omitempty"`
	RareFlowThreshold          float64                    `yaml:"rare_flow_threshold,omitempty"`
	PortScanThreshold          int                        `yaml:"port_scan_threshold,omitempty"`
	PortScanWindowSeconds      int                        `yaml:"port_scan_window_seconds,omitempty"`
	AsymmetricRatio            float64                    `yaml:"asymmetric_ratio,omitempty"`
	PublicEgressKnownGood      []string                   `yaml:"public_egress_known_good,omitempty"`
	AllowedNamespacePairs      map[string][]string        `yaml:"allowed_namespace_pairs,omitempty"`
	PerNamespaceProfiles       map[string]config.Profile  `yaml:"per_namespace_profiles,omitempty"`
	KnownGoodExternalEndpoints []string                   `yaml:"known_good_external_endpoints,omitempty"`
	PublicEgressAllowlistCIDRs []string                   `yaml:"public_egress_allowlist_cidrs,omitempty"`
	ApiserverIngressPorts      []config.PortSpec          `yaml:"apiserver_ingress_ports,omitempty"`
	ApiserverEgressPorts       []config.PortSpec          `yaml:"apiserver_egress_ports,omitempty"`
	PublicServices             []config.PublicServiceSpec `yaml:"public_services,omitempty"`
	ApiserverWorkloadSelector  *config.WorkloadSelector   `yaml:"apiserver_workload_selector,omitempty"`
	NodeCIDRs                  []string                   `yaml:"node_cidrs,omitempty"`
	AlwaysAllowDNS             bool                       `yaml:"always_allow_dns,omitempty"`
}

func marshalConfigOutput(v map[string]string) (string, error) {
	cfg := configOutput{
		ClusterCIDRs:               splitCSV(v["cluster_cidrs"]),
		APIServerCIDRs:             splitCSV(v["apiserver_cidrs"]),
		ExcludedNamespaces:         splitCSV(v["excluded_namespaces"]),
		KubeDNSPorts:               parsePortSpecs(v["kube_dns_ports"]),
		RareFlowThreshold:          parseFloatVal(v["rare_flow_threshold"]),
		PortScanThreshold:          parseIntVal(v["port_scan_threshold"]),
		PortScanWindowSeconds:      parseIntVal(v["port_scan_window_seconds"]),
		AsymmetricRatio:            parseFloatVal(v["asymmetric_ratio"]),
		PublicEgressKnownGood:      splitCSV(v["public_egress_known_good"]),
		KnownGoodExternalEndpoints: splitCSV(v["known_good_external_endpoints"]),
		PublicEgressAllowlistCIDRs: splitCSV(v["public_egress_allowlist_cidrs"]),
		ApiserverIngressPorts:      parsePortSpecs(v["apiserver_ingress_ports"]),
		ApiserverEgressPorts:       parsePortSpecs(v["apiserver_egress_ports"]),
		NodeCIDRs:                  splitCSV(v["node_cidrs"]),
		AlwaysAllowDNS:             v["always_allow_dns"] == "true",
	}

	if raw := strings.TrimSpace(v["allowed_namespace_pairs"]); raw != "" {
		var pairs map[string][]string
		if err := yamlutil.Unmarshal([]byte(raw), &pairs); err == nil {
			cfg.AllowedNamespacePairs = pairs
		}
	}
	if raw := strings.TrimSpace(v["per_namespace_profiles"]); raw != "" {
		var profiles map[string]config.Profile
		if err := yamlutil.Unmarshal([]byte(raw), &profiles); err == nil {
			cfg.PerNamespaceProfiles = profiles
		}
	}
	if raw := strings.TrimSpace(v["public_services"]); raw != "" {
		var services []config.PublicServiceSpec
		if err := yamlutil.Unmarshal([]byte(raw), &services); err == nil {
			cfg.PublicServices = services
		}
	}
	if raw := strings.TrimSpace(v["apiserver_workload_selector"]); raw != "" {
		var sel config.WorkloadSelector
		if err := yamlutil.Unmarshal([]byte(raw), &sel); err == nil {
			cfg.ApiserverWorkloadSelector = &sel
		}
	}

	out, err := yamlutil.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePortSpecs(s string) []config.PortSpec {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var specs []config.PortSpec
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		protoPort := strings.SplitN(p, "/", 2)
		if len(protoPort) != 2 {
			continue
		}
		port, err := strconv.Atoi(protoPort[1])
		if err != nil {
			continue
		}
		specs = append(specs, config.PortSpec{
			Protocol: strings.ToUpper(protoPort[0]),
			Port:     port,
		})
	}
	return specs
}

func parseFloatVal(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func parseIntVal(s string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(s))
	return i
}

func stripAllAnsi(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// stripFilePickerCursor removes the Bubbles filepicker cursor prefix from a
// line so we can re-render the first file item without the cursor.
func stripFilePickerCursor(line string) string {
	line = stripAllAnsi(line)
	line = strings.TrimPrefix(line, "> ")
	return line
}
