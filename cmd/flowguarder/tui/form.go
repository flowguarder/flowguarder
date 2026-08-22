package tui

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/flowguarder/flowguarder/pkg/config"
	yamlutil "sigs.k8s.io/yaml"
)

// focusColor is the K8s blue ANSI color used for the focus indicator.
const focusColor = lipgloss.Color("63")

// FormField is a single reusable form input primitive for the unified TUI.
//
// All implementations are value types: every method uses a value receiver so
// that fields can be stored in a []FormField slice and updated by reassignment
// (the Bubble Tea value-semantics convention). Fields never perform I/O.
type FormField interface {
	// Update handles a tea.Msg (typically tea.KeyMsg) and returns the updated
	// field plus an optional tea.Cmd.
	Update(msg tea.Msg) (FormField, tea.Cmd)
	// View renders the field with its focus indicator.
	View() string
	// Value returns the field's current value as a string.
	Value() string
	// Label returns the field's label (used as the key in Form.Values()).
	Label() string
	// Description returns the field's help text.
	Description() string
	// Focused reports whether the field currently holds focus.
	Focused() bool
	// Focus returns the field with focus engaged.
	Focus() FormField
	// Blur returns the field with focus disengaged.
	Blur() FormField
}

// focusPrefix returns the leading indicator for a field: a K8s-blue "> "
// when focused, or two plain spaces otherwise.
func focusPrefix(focused bool) string {
	if focused {
		return lipgloss.NewStyle().Foreground(focusColor).Render("> ")
	}
	return "  "
}

// allDigits reports whether s consists solely of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// TextField
// ---------------------------------------------------------------------------

// TextField is a single-line text input field wrapping textinput.Model.
type TextField struct {
	label       string
	placeholder string
	value       string
	focused     bool
	charLimit   int
	width       int
	description string
	input       textinput.Model
}

var _ FormField = (*TextField)(nil)

// NewTextField creates a TextField with the given label, placeholder, and help
// description.
func NewTextField(label, placeholder, description string) TextField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	f := TextField{
		label:       label,
		placeholder: placeholder,
		description: description,
		input:       ti,
	}
	f.input.CharLimit = f.charLimit
	f.input.Width = f.width
	return f
}

// Update handles text input keys (typing, backspace, cursor movement).
func (f TextField) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	f.value = f.input.Value()
	return f, cmd
}

// View renders the field with its focus indicator.
func (f TextField) View() string {
	return focusPrefix(f.focused) + f.label + ": " + f.input.View()
}

// Value returns the current text.
func (f TextField) Value() string { return f.value }

// Label returns the field label.
func (f TextField) Label() string { return f.label }

// Description returns the help text.
func (f TextField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f TextField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f TextField) Focus() FormField {
	f.focused = true
	f.input.Focus()
	return f
}

// Blur disengages focus on the field.
func (f TextField) Blur() FormField {
	f.focused = false
	f.input.Blur()
	return f
}

// ---------------------------------------------------------------------------
// NumberField
// ---------------------------------------------------------------------------

// NumberField is a numeric input field that restricts input to ASCII digits.
type NumberField struct {
	label       string
	placeholder string
	value       string
	focused     bool
	charLimit   int
	width       int
	description string
	input       textinput.Model
}

var _ FormField = (*NumberField)(nil)

// NewNumberField creates a NumberField with the given label, placeholder, and
// help description.
func NewNumberField(label, placeholder, description string) NumberField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	f := NumberField{
		label:       label,
		placeholder: placeholder,
		description: description,
		input:       ti,
	}
	f.input.CharLimit = f.charLimit
	f.input.Width = f.width
	return f
}

// Update handles numeric input keys, rejecting any non-digit runes.
func (f NumberField) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.Type == tea.KeyRunes && !allDigits(string(key.Runes)) {
			return f, nil
		}
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	f.value = f.input.Value()
	return f, cmd
}

// View renders the field with its focus indicator.
func (f NumberField) View() string {
	return focusPrefix(f.focused) + f.label + ": " + f.input.View()
}

// Value returns the current numeric text.
func (f NumberField) Value() string { return f.value }

// ValueInt returns the parsed integer value (0 if empty or invalid).
func (f NumberField) ValueInt() int {
	v, err := strconv.Atoi(strings.TrimSpace(f.value))
	if err != nil {
		return 0
	}
	return v
}

// Label returns the field label.
func (f NumberField) Label() string { return f.label }

// Description returns the help text.
func (f NumberField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f NumberField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f NumberField) Focus() FormField {
	f.focused = true
	f.input.Focus()
	return f
}

// Blur disengages focus on the field.
func (f NumberField) Blur() FormField {
	f.focused = false
	f.input.Blur()
	return f
}

// ---------------------------------------------------------------------------
// BoolField
// ---------------------------------------------------------------------------

// BoolField is a true/false toggle rendered as a checkbox.
type BoolField struct {
	label       string
	value       bool
	focused     bool
	description string
}

var _ FormField = (*BoolField)(nil)

// NewBoolField creates a BoolField with the given label and help description.
func NewBoolField(label, description string) BoolField {
	return BoolField{label: label, description: description}
}

// Update toggles the value on space or enter when focused.
func (f BoolField) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == " " || key.String() == "enter" {
			f.value = !f.value
		}
	}
	return f, nil
}

// View renders the checkbox with its focus indicator.
func (f BoolField) View() string {
	mark := " "
	if f.value {
		mark = "x"
	}
	return focusPrefix(f.focused) + f.label + ": [" + mark + "]"
}

// Value returns "true" or "false".
func (f BoolField) Value() string {
	if f.value {
		return "true"
	}
	return "false"
}

// ValueBool returns the boolean value.
func (f BoolField) ValueBool() bool { return f.value }

// Label returns the field label.
func (f BoolField) Label() string { return f.label }

// Description returns the help text.
func (f BoolField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f BoolField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f BoolField) Focus() FormField {
	f.focused = true
	return f
}

// Blur disengages focus on the field.
func (f BoolField) Blur() FormField {
	f.focused = false
	return f
}

// ---------------------------------------------------------------------------
// MultiSelectField
// ---------------------------------------------------------------------------

// MultiSelectField is a tag-style multi-select over a fixed set of options.
type MultiSelectField struct {
	label       string
	options     []string
	selected    map[string]bool
	focused     bool
	cursor      int
	description string
}

var _ FormField = (*MultiSelectField)(nil)

// NewMultiSelectField creates a MultiSelectField over the given options.
func NewMultiSelectField(label string, options []string, description string) MultiSelectField {
	return MultiSelectField{
		label:       label,
		options:     append([]string(nil), options...),
		selected:    make(map[string]bool),
		description: description,
	}
}

// Update moves the cursor with up/down and toggles the highlighted option with
// space or enter.
func (f MultiSelectField) Update(msg tea.Msg) (FormField, tea.Cmd) {
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
	case " ", "enter":
		if f.cursor >= 0 && f.cursor < len(f.options) {
			opt := f.options[f.cursor]
			f.selected[opt] = !f.selected[opt]
		}
	}
	return f, nil
}

// View renders the option list with cursor and selection markers.
func (f MultiSelectField) View() string {
	var b strings.Builder
	b.WriteString(focusPrefix(f.focused))
	b.WriteString(f.label)
	b.WriteString(":\n")
	for i, o := range f.options {
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

// Value returns the selected options as a sorted, comma-separated string.
func (f MultiSelectField) Value() string {
	sel := make([]string, 0, len(f.options))
	for _, o := range f.options {
		if f.selected[o] {
			sel = append(sel, o)
		}
	}
	sort.Strings(sel)
	return strings.Join(sel, ",")
}

// Label returns the field label.
func (f MultiSelectField) Label() string { return f.label }

// Description returns the help text.
func (f MultiSelectField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f MultiSelectField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f MultiSelectField) Focus() FormField {
	f.focused = true
	return f
}

// Blur disengages focus on the field.
func (f MultiSelectField) Blur() FormField {
	f.focused = false
	return f
}

// ---------------------------------------------------------------------------
// SelectField
// ---------------------------------------------------------------------------

// SelectField is a single-select radio-style field over a fixed set of options.
type SelectField struct {
	label       string
	options     []string
	selected    int
	cursor      int
	focused     bool
	description string
}

var _ FormField = (*SelectField)(nil)

func NewSelectField(label string, options []string, defaultValue string, description string) SelectField {
	sf := SelectField{
		label:       label,
		options:     append([]string(nil), options...),
		description: description,
	}
	for i, o := range sf.options {
		if o == defaultValue {
			sf.cursor = i
			sf.selected = i
			break
		}
	}
	return sf
}

func (f SelectField) Update(msg tea.Msg) (FormField, tea.Cmd) {
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
	case " ", "enter":
		f.selected = f.cursor
	}
	return f, nil
}

func (f SelectField) View() string {
	var b strings.Builder
	b.WriteString(focusPrefix(f.focused))
	b.WriteString(f.label)
	b.WriteString(":\n")
	for i, o := range f.options {
		mark := " "
		if i == f.selected {
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

func (f SelectField) Value() string {
	if f.selected >= 0 && f.selected < len(f.options) {
		return f.options[f.selected]
	}
	return ""
}

func (f SelectField) Label() string       { return f.label }
func (f SelectField) Description() string { return f.description }
func (f SelectField) Focused() bool       { return f.focused }
func (f SelectField) Focus() FormField    { f.focused = true; return f }
func (f SelectField) Blur() FormField     { f.focused = false; return f }

// ---------------------------------------------------------------------------
// PortListField
// ---------------------------------------------------------------------------

// PortListField collects port/protocol specs (e.g. "TCP/8080") entered one at a
// time into a text input, displaying the accumulated specs as a list.
type PortListField struct {
	label       string
	placeholder string
	specs       []string
	input       textinput.Model
	focused     bool
	description string
}

var _ FormField = (*PortListField)(nil)

// NewPortListField creates a PortListField with the given label, placeholder,
// and help description.
func NewPortListField(label, placeholder, description string) PortListField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	return PortListField{
		label:       label,
		placeholder: placeholder,
		description: description,
		input:       ti,
	}
}

// Update adds the current input as a new spec on enter, removes the last spec
// when backspace is pressed on an empty input, and otherwise forwards to the
// underlying text input.
func (f PortListField) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return f, nil
	}
	switch key.Type {
	case tea.KeyEnter:
		v := strings.TrimSpace(f.input.Value())
		if v != "" {
			f.specs = append(f.specs, v)
			f.input.SetValue("")
		}
		return f, nil
	case tea.KeyBackspace:
		if strings.TrimSpace(f.input.Value()) == "" && len(f.specs) > 0 {
			f.specs = f.specs[:len(f.specs)-1]
			return f, nil
		}
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return f, cmd
}

// View renders the input line followed by the accumulated specs.
func (f PortListField) View() string {
	var b strings.Builder
	b.WriteString(focusPrefix(f.focused))
	b.WriteString(f.label)
	b.WriteString(": ")
	b.WriteString(f.input.View())
	for _, s := range f.specs {
		b.WriteString("\n      - ")
		b.WriteString(s)
	}
	return b.String()
}

// Value returns the specs as a semicolon-separated string.
func (f PortListField) Value() string {
	return strings.Join(f.specs, ";")
}

// Label returns the field label.
func (f PortListField) Label() string { return f.label }

// Description returns the help text.
func (f PortListField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f PortListField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f PortListField) Focus() FormField {
	f.focused = true
	f.input.Focus()
	return f
}

// Blur disengages focus on the field.
func (f PortListField) Blur() FormField {
	f.focused = false
	f.input.Blur()
	return f
}

// ---------------------------------------------------------------------------
// YAMLField
// ---------------------------------------------------------------------------

// YAMLField is a multi-line YAML textarea that starts collapsed.
// Enter toggles between collapsed (single-line preview) and expanded (full editor).
type YAMLField struct {
	label       string
	value       string
	focused     bool
	collapsed   bool
	description string
	input       textarea.Model
}

var _ FormField = (*YAMLField)(nil)

// NewYAMLField creates a YAMLField with the given label and help description.
func NewYAMLField(label, description string) YAMLField {
	ta := textarea.New()
	ta.SetWidth(40)
	ta.SetHeight(5)
	return YAMLField{
		label:       label,
		description: description,
		collapsed:   true,
		input:       ta,
	}
}

// Update forwards the message to the underlying textarea when focused.
// Enter toggles between collapsed (single-line) and expanded (full editor).
func (f YAMLField) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !f.focused {
		return f, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
		f.collapsed = !f.collapsed
		if f.collapsed {
			f.input.Blur()
		} else {
			f.input.Focus()
		}
		return f, nil
	}
	if f.collapsed {
		return f, nil
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	f.value = f.input.Value()
	return f, cmd
}

// View renders the field: collapsed shows a single-line preview, expanded shows the full editor.
func (f YAMLField) View() string {
	if f.collapsed {
		preview := f.value
		if preview == "" {
			preview = "(Enter to edit)"
		}
		lines := strings.Split(preview, "\n")
		if len(lines) > 1 {
			preview = lines[0] + "…"
		}
		return focusPrefix(f.focused) + f.label + ": " + preview
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Width(42)
	return focusPrefix(f.focused) + f.label + ":\n" + box.Render(f.input.View())
}

// Value returns the raw YAML text.
func (f YAMLField) Value() string { return f.value }

// Label returns the field label.
func (f YAMLField) Label() string { return f.label }

// Description returns the help text.
func (f YAMLField) Description() string { return f.description }

// Focused reports whether the field is focused.
func (f YAMLField) Focused() bool { return f.focused }

// Focus engages focus on the field.
func (f YAMLField) Focus() FormField {
	f.focused = true
	if !f.collapsed {
		f.input.Focus()
	}
	return f
}

// Blur disengages focus on the field.
func (f YAMLField) Blur() FormField {
	f.focused = false
	f.input.Blur()
	return f
}

// ---------------------------------------------------------------------------
// Form container
// ---------------------------------------------------------------------------

// Form holds an ordered list of fields and manages focus cycling among them.
type Form struct {
	fields     []FormField
	focusIndex int
	viewHeight int // <=0 means unbounded (current behaviour); >0 clamps View() to h lines
}

// NewForm creates a Form from the given fields, focusing the first field.
func NewForm(fields ...FormField) Form {
	f := Form{fields: fields, focusIndex: 0}
	if len(f.fields) > 0 {
		f.fields[0] = f.fields[0].Focus()
	}
	return f
}

// Update forwards the message to the focused field. Up and Down cycle focus
// among the fields; all other messages are handled by the focused field.
// When the focused field is a MultiSelectField, up/down are passed through so
// the field can move its internal cursor between options.
func (f Form) Update(msg tea.Msg) (Form, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k", "down", "j":
			if fidx := f.focusIndex; fidx >= 0 && fidx < len(f.fields) {
				if ms, ok := f.fields[fidx].(MultiSelectField); ok {
					oldCursor := ms.cursor
					updated, cmd := f.fields[fidx].Update(msg)
					f.fields[fidx] = updated
					if newMs, ok := f.fields[fidx].(MultiSelectField); ok {
						if newMs.cursor == oldCursor {
							if key.String() == "up" || key.String() == "k" {
								return f.cycleFocus(-1), nil
							}
							return f.cycleFocus(1), nil
						}
					}
					return f, cmd
				}
				if sf, ok := f.fields[fidx].(SelectField); ok {
					oldCursor := sf.cursor
					updated, cmd := f.fields[fidx].Update(msg)
					f.fields[fidx] = updated
					if newSf, ok := f.fields[fidx].(SelectField); ok {
						if newSf.cursor == oldCursor {
							if key.String() == "up" || key.String() == "k" {
								return f.cycleFocus(-1), nil
							}
							return f.cycleFocus(1), nil
						}
					}
					return f, cmd
				}
			}
		}
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			return f.cycleFocus(-1), nil
		case "down", "j":
			return f.cycleFocus(1), nil
		}
	}
	if len(f.fields) == 0 || f.focusIndex < 0 || f.focusIndex >= len(f.fields) {
		return f, nil
	}
	updated, cmd := f.fields[f.focusIndex].Update(msg)
	f.fields[f.focusIndex] = updated
	return f, cmd
}

// cycleFocus blurs the current field, moves the focus index by dir (wrapping),
// and focuses the new field.
func (f Form) cycleFocus(dir int) Form {
	if len(f.fields) == 0 {
		return f
	}
	f.fields[f.focusIndex] = f.fields[f.focusIndex].Blur()
	f.focusIndex += dir
	switch {
	case f.focusIndex < 0:
		f.focusIndex = len(f.fields) - 1
	case f.focusIndex >= len(f.fields):
		f.focusIndex = 0
	}
	f.fields[f.focusIndex] = f.fields[f.focusIndex].Focus()
	return f
}

// View renders all fields vertically, each with its label and focus indicator.
// If setViewHeight has been called with h>0, only the lines within that
// budget are returned; the focused field is always fully visible in the window.
func (f Form) View() string {
	if len(f.fields) == 0 {
		return ""
	}
	// Render each field and collect per-field line ranges.
	type fieldLines struct {
		start, end int
		lines      []string
	}
	all := make([]fieldLines, 0, len(f.fields))
	idx := 0
	for _, field := range f.fields {
		raw := field.View()
		lines := strings.Split(raw, "\n")
		start := idx
		idx += len(lines)
		all = append(all, fieldLines{start: start, end: idx, lines: lines})
	}
	total := idx
	vh := f.viewHeight
	fi := f.focusIndex

	// Unbounded budget: return everything.
	if vh <= 0 || vh >= total {
		parts := make([]string, 0, len(f.fields))
		for _, field := range f.fields {
			parts = append(parts, field.View())
		}
		return strings.Join(parts, "\n")
	}

	// Determine scroll window so the focused field is fully visible.
	sc := 0
	if fi >= 0 && fi < len(all) {
		fl := all[fi]
		// If focused field itself exceeds the budget, align to top.
		if fl.end-fl.start <= vh {
			if fl.start < sc {
				sc = fl.start
			}
			if fl.end > sc+vh {
				sc = fl.end - vh
			}
		} else {
			sc = fl.start // show head of oversized field
		}
	}
	if sc < 0 {
		sc = 0
	}
	if sc+vh > total {
		sc = total - vh
	}
	if sc < 0 {
		sc = 0
	}

	chunk := make([]string, 0, vh)
	for i := sc; i < sc+vh && i < total; i++ {
		for _, fl := range all {
			if i >= fl.start && i < fl.end {
				chunk = append(chunk, fl.lines[i-fl.start])
				break
			}
		}
	}
	return strings.Join(chunk, "\n")
}

// FocusedField returns the currently focused field (nil if the form is empty
// or no field has focus).
func (f Form) FocusedField() FormField {
	if len(f.fields) == 0 || f.focusIndex < 0 || f.focusIndex >= len(f.fields) {
		return nil
	}
	return f.fields[f.focusIndex]
}

// FocusedIndex returns the index of the currently focused field.
func (f Form) FocusedIndex() int { return f.focusIndex }

// SetFocus moves focus to the field at the given index. Out-of-range indices
// are ignored.
func (f Form) SetFocus(index int) Form {
	if index < 0 || index >= len(f.fields) {
		return f
	}
	if f.focusIndex >= 0 && f.focusIndex < len(f.fields) {
		f.fields[f.focusIndex] = f.fields[f.focusIndex].Blur()
	}
	f.focusIndex = index
	f.fields[f.focusIndex] = f.fields[f.focusIndex].Focus()
	return f
}

// Values returns a map of field label to current value for all fields.
func (f Form) Values() map[string]string {
	m := make(map[string]string, len(f.fields))
	for _, field := range f.fields {
		m[field.Label()] = field.Value()
	}
	return m
}

// setFieldValue sets the value of a single form field by label.
func (f *Form) setFieldValue(label, value string) {
	for i, field := range f.fields {
		if field.Label() == label {
			f.fields[i] = f.setFormFieldValue(field, value)
			return
		}
	}
}

// setViewHeight sets the maximum number of lines the form may render.
// Zero or negative means unbounded (current pre-fix behaviour).
func (f Form) setViewHeight(h int) Form {
	f.viewHeight = h
	return f
}

// setFormFieldValue delegates to the concrete field type.
func (f *Form) setFormFieldValue(field FormField, value string) FormField {
	switch v := field.(type) {
	case TextField:
		v.input.SetValue(value)
		v.value = value
		return v
	case NumberField:
		v.input.SetValue(value)
		v.value = value
		return v
	case BoolField:
		v.value = value == "true"
		return v
	case MultiSelectField:
		// value is comma-separated; match against options.
		selected := make(map[string]bool)
		for _, opt := range v.options {
			selected[opt] = false
		}
		if value != "" {
			for _, tag := range strings.Split(value, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					selected[tag] = true
				}
			}
		}
		v.selected = selected
		return v
	case PortListField:
		// value is semicolon-separated (e.g. "UDP/53;TCP/53").
		v.specs = []string{}
		if value != "" {
			for _, spec := range strings.Split(value, ";") {
				spec = strings.TrimSpace(spec)
				if spec != "" {
					v.specs = append(v.specs, spec)
				}
			}
		}
		return v
	case YAMLField:
		v.input.SetValue(value)
		v.value = value
		return v
	case SelectField:
		for i, opt := range v.options {
			if opt == value {
				v.cursor = i
				v.selected = i
				break
			}
		}
		if v.selected < 0 || v.selected >= len(v.options) {
			v.cursor = 0
			v.selected = 0
		}
		return v
	default:
		return field
	}
}

// SetConfig populates form fields from a loaded config.Config.
// It only touches fields that have a matching label in the form.
func (f *Form) SetConfig(cfg config.Config) {
	f.setFieldValue("cluster_cidrs", joinCIDR(cfg.ClusterCIDRs))
	f.setFieldValue("apiserver_cidrs", joinCIDR(cfg.APIServerCIDRs))
	f.setFieldValue("excluded_namespaces", joinCSV(cfg.ExcludedNamespaces))
	f.setFieldValue("kube_dns_ports", joinPortSpec(cfg.KubeDNSPorts))
	f.setFieldValue("rare_flow_threshold", strconv.FormatFloat(cfg.RareFlowThreshold, 'f', -1, 64))
	f.setFieldValue("port_scan_threshold", strconv.Itoa(cfg.PortScanThreshold))
	f.setFieldValue("port_scan_window_seconds", strconv.Itoa(cfg.PortScanWindowSeconds))
	f.setFieldValue("asymmetric_ratio", strconv.FormatFloat(cfg.AsymmetricRatio, 'f', -1, 64))
	f.setFieldValue("public_egress_known_good", joinCSV(cfg.PublicEgressKnownGood))
	f.setFieldValue("known_good_external_endpoints", joinCSV(cfg.KnownGoodExternalEndpoints))
	f.setFieldValue("public_egress_allowlist_cidrs", joinCIDR(cfg.PublicEgressAllowlistCIDRs))
	f.setFieldValue("apiserver_ingress_ports", joinPortSpec(cfg.ApiserverIngressPorts))
	f.setFieldValue("apiserver_egress_ports", joinPortSpec(cfg.ApiserverEgressPorts))
	f.setFieldValue("node_cidrs", joinCSV(cfg.NodeCIDRs))

	if idx := f.fieldIndex("always_allow_dns"); idx >= 0 {
		if bf, ok := f.fields[idx].(BoolField); ok {
			bf.value = cfg.AlwaysAllowDNS
			f.fields[idx] = bf
		}
	}
	if cfg.ApiserverWorkloadSelector != nil {
		if b, err := yamlutil.Marshal(cfg.ApiserverWorkloadSelector); err == nil {
			f.setFieldValue("apiserver_workload_selector", strings.TrimSpace(string(b)))
		}
	}
	if len(cfg.AllowedNamespacePairs) > 0 {
		if b, err := yamlutil.Marshal(cfg.AllowedNamespacePairs); err == nil {
			f.setFieldValue("allowed_namespace_pairs", strings.TrimSpace(string(b)))
		}
	}
	if len(cfg.PerNamespaceProfiles) > 0 {
		if b, err := yamlutil.Marshal(cfg.PerNamespaceProfiles); err == nil {
			f.setFieldValue("per_namespace_profiles", strings.TrimSpace(string(b)))
		}
	}
	if len(cfg.PublicServices) > 0 {
		if b, err := yamlutil.Marshal(cfg.PublicServices); err == nil {
			f.setFieldValue("public_services", strings.TrimSpace(string(b)))
		}
	}
}

func (f *Form) fieldIndex(label string) int {
	for i, field := range f.fields {
		if field.Label() == label {
			return i
		}
	}
	return -1
}

func joinCIDR(cidrs []*net.IPNet) string {
	var parts []string
	for _, c := range cidrs {
		if c != nil {
			parts = append(parts, c.String())
		}
	}
	return strings.Join(parts, ",")
}

func joinPortSpec(specs []config.PortSpec) string {
	var parts []string
	for _, s := range specs {
		if s.Protocol != "" {
			parts = append(parts, s.String())
		}
	}
	return strings.Join(parts, ";")
}

func joinCSV(ss []string) string {
	return strings.Join(ss, ", ")
}
