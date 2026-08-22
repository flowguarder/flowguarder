package tui

import (
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// analyzeReportTypes is the fixed, ordered list of valid report types shown in
// the Analyze tab. The order here is the display order; Values() and View()
// iterate a sorted copy of these keys for deterministic output. Because the UI
// only ever renders these six entries, an unknown report name is impossible to
// select through the interface.
var analyzeReportTypes = []string{
	"top-flows",
	"uncovered",
	"coverage",
	"egress-world",
	"drops",
	"anomalies",
}

// AnalyzeRunMsg is emitted when the Analyze Run button is activated. The CLI
// layer (outside the TUI) is responsible for acting on it; the TUI itself never
// performs I/O or runs the pipeline.
type AnalyzeRunMsg struct{}

// RunButton is the Run action rendered at the bottom of the Analyze reports
// group. It is styled with a K8s-blue (ANSI 63) background when focused.
type RunButton struct {
	label string
}

// NewRunButton creates a RunButton with the given label.
func NewRunButton(label string) RunButton {
	return RunButton{label: label}
}

// View renders the button. When focused it uses a bold white-on-K8s-blue style;
// when idle it is rendered in K8s blue text only.
func (b RunButton) View(focused bool) string {
	if focused {
		return lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("63")).
			Padding(0, 3).
			Render(b.label + " ▶")
	}
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("63")).
		Padding(0, 3).
		Render(b.label + " ▶")
}

// Command returns a tea.Cmd that emits an AnalyzeRunMsg when the button is
// activated.
func (b RunButton) Command() tea.Cmd {
	return func() tea.Msg {
		return AnalyzeRunMsg{}
	}
}

// AnalyzeReports is a multi-select toggle group for report types. It implements FormField so it can be embedded in the unified TUI's
// focus model. Toggle state lives in a map[string]bool and is always iterated
// in sorted-key order for deterministic rendering and output.
type AnalyzeReports struct {
	label       string
	options     []string
	selected    map[string]bool
	cursor      int // 0..len(options)-1 for toggles
	focused     bool
	description string
}

var _ FormField = (*AnalyzeReports)(nil)

// NewAnalyzeReports creates an AnalyzeReports group over the fixed set of valid
// report types.
func NewAnalyzeReports(label, description string) AnalyzeReports {
	opts := append([]string(nil), analyzeReportTypes...)
	return AnalyzeReports{
		label:       label,
		options:     opts,
		selected:    make(map[string]bool),
		description: description,
	}
}

// sortedOptions returns the report-type options in sorted order. Iterating this
// slice (rather than the map directly) guarantees deterministic display and
// output ordering.
func (f AnalyzeReports) sortedOptions() []string {
	opts := append([]string(nil), f.options...)
	sort.Strings(opts)
	return opts
}

// Update moves the cursor with up/down, toggles the highlighted report on
// space/enter.
func (f AnalyzeReports) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return f, nil
	}
	switch key.String() {
	case "up", "k":
		if f.cursor > 0 {
			f.cursor--
		}
	case "down", "j":
		if f.cursor < len(f.options)-1 {
			f.cursor++
		}
	case "enter", " ":
		opts := f.sortedOptions()
		if f.cursor < len(opts) {
			opt := opts[f.cursor]
			f.selected[opt] = !f.selected[opt]
		}
	}
	return f, nil
}

// View renders the report toggles with [x]/[ ] checkboxes.
func (f AnalyzeReports) View() string {
	var b strings.Builder
	b.WriteString(sectionTitle(f.focused, f.label+":"))
	b.WriteString("\n")

	opts := f.sortedOptions()
	for i, o := range opts {
		mark := " "
		if f.selected[o] {
			mark = "x"
		}
		cursor := " "
		if f.focused && i == f.cursor {
			cursor = ">"
		}
		b.WriteString("    ")
		b.WriteString(cursor)
		b.WriteString(" [")
		b.WriteString(mark)
		b.WriteString("] ")
		b.WriteString(o)
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// Value returns the selected report types as a sorted, comma-separated string
// (FormField contract).
func (f AnalyzeReports) Value() string {
	return strings.Join(f.Values(), ",")
}

// Values returns the selected report types as a sorted []string. Only the six
// valid types can ever appear because the UI only renders those.
func (f AnalyzeReports) Values() []string {
	sel := make([]string, 0, len(f.options))
	for _, o := range f.sortedOptions() {
		if f.selected[o] {
			sel = append(sel, o)
		}
	}
	return sel
}

// Label returns the field label.
func (f AnalyzeReports) Label() string { return f.label }

// Description returns the help text.
func (f AnalyzeReports) Description() string { return f.description }

// Focused reports whether the field currently holds focus.
func (f AnalyzeReports) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f AnalyzeReports) Focus() FormField {
	f.focused = true
	return f
}

// Blur disengages focus on the field.
func (f AnalyzeReports) Blur() FormField {
	f.focused = false
	return f
}
