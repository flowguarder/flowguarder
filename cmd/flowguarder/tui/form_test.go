package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// keyMsg builds a tea.KeyMsg from a key string for test brevity.
func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestFormFieldTextField(t *testing.T) {
	t.Parallel()

	tf := NewTextField("Name", "enter name", "the workload name")
	if tf.Label() != "Name" {
		t.Fatalf("Label() = %q, want %q", tf.Label(), "Name")
	}
	if tf.Description() != "the workload name" {
		t.Fatalf("Description() = %q", tf.Description())
	}
	if tf.Focused() {
		t.Fatal("new field should not be focused")
	}
	if tf.Value() != "" {
		t.Fatalf("Value() = %q, want empty", tf.Value())
	}

	// Focus then type.
	tf = tf.Focus().(TextField)
	if !tf.Focused() {
		t.Fatal("Focus() should set focused")
	}
	updated, _ := tf.Update(keyMsg("ab"))
	tf = updated.(TextField)
	if tf.Value() != "ab" {
		t.Fatalf("Value() after typing = %q, want %q", tf.Value(), "ab")
	}

	// Blur clears focus but keeps value.
	tf = tf.Blur().(TextField)
	if tf.Focused() {
		t.Fatal("Blur() should clear focused")
	}
	// Update while blurred is a no-op.
	updated, _ = tf.Update(keyMsg("c"))
	tf = updated.(TextField)
	if tf.Value() != "ab" {
		t.Fatalf("Value() while blurred = %q, want %q", tf.Value(), "ab")
	}

	// View contains the label and focus indicator when focused.
	tf = tf.Focus().(TextField)
	view := tf.View()
	if !strings.Contains(view, "Name:") {
		t.Fatalf("View() = %q, want it to contain label", view)
	}
	if !strings.Contains(view, "> ") {
		t.Fatalf("View() = %q, want focus indicator", view)
	}
}

func TestFormFieldNumberField(t *testing.T) {
	t.Parallel()

	nf := NewNumberField("Port", "8080", "listen port")
	nf = nf.Focus().(NumberField)
	updated, _ := nf.Update(keyMsg("1"))
	nf = updated.(NumberField)
	updated, _ = nf.Update(keyMsg("2"))
	nf = updated.(NumberField)
	if nf.Value() != "12" {
		t.Fatalf("Value() = %q, want %q", nf.Value(), "12")
	}
	updated, _ = nf.Update(keyMsg("a"))
	nf = updated.(NumberField)
	if nf.Value() != "12" {
		t.Fatalf("Value() = %q, want %q (letters rejected)", nf.Value(), "12")
	}
	updated, _ = nf.Update(keyMsg("3"))
	nf = updated.(NumberField)
	if nf.Value() != "123" {
		t.Fatalf("Value() = %q, want %q", nf.Value(), "123")
	}
	if nf.ValueInt() != 123 {
		t.Fatalf("ValueInt() = %d, want %d", nf.ValueInt(), 123)
	}

	// Empty / invalid parses to 0.
	empty := NewNumberField("Port", "", "p").Focus().(NumberField)
	if empty.ValueInt() != 0 {
		t.Fatalf("ValueInt() empty = %d, want 0", empty.ValueInt())
	}
}

func TestFormFieldBoolField(t *testing.T) {
	t.Parallel()

	bf := NewBoolField("Strict", "strict mode")
	if bf.ValueBool() {
		t.Fatal("default bool should be false")
	}
	bf = bf.Focus().(BoolField)
	updated, _ := bf.Update(tea.KeyMsg{Type: tea.KeySpace})
	bf = updated.(BoolField)
	if !bf.ValueBool() {
		t.Fatal("space should toggle to true")
	}
	if bf.Value() != "true" {
		t.Fatalf("Value() = %q, want %q", bf.Value(), "true")
	}
	updated, _ = bf.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bf = updated.(BoolField)
	if bf.ValueBool() {
		t.Fatal("enter should toggle back to false")
	}
	// View shows checkbox.
	if !strings.Contains(bf.View(), "[ ]") {
		t.Fatalf("View() = %q, want unchecked box", bf.View())
	}
	bf = bf.Focus().(BoolField)
	bf, _ = func() (BoolField, tea.Cmd) {
		u, c := bf.Update(tea.KeyMsg{Type: tea.KeySpace})
		return u.(BoolField), c
	}()
	if !strings.Contains(bf.View(), "[x]") {
		t.Fatalf("View() = %q, want checked box", bf.View())
	}
}

func TestFormFieldMultiSelectField(t *testing.T) {
	t.Parallel()

	ms := NewMultiSelectField("Protocols", []string{"TCP", "UDP", "SCTP"}, "pick protocols")
	if len(ms.options) != 3 {
		t.Fatalf("options len = %d, want 3", len(ms.options))
	}
	ms = ms.Focus().(MultiSelectField)
	// Toggle first option (TCP).
	updated, _ := ms.Update(tea.KeyMsg{Type: tea.KeySpace})
	ms = updated.(MultiSelectField)
	if !ms.selected["TCP"] {
		t.Fatal("TCP should be selected")
	}
	// Move down to UDP and toggle.
	updated, _ = ms.Update(tea.KeyMsg{Type: tea.KeyDown})
	ms = updated.(MultiSelectField)
	if ms.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", ms.cursor)
	}
	updated, _ = ms.Update(tea.KeyMsg{Type: tea.KeySpace})
	ms = updated.(MultiSelectField)
	if !ms.selected["UDP"] {
		t.Fatal("UDP should be selected")
	}
	// Value is sorted, comma-separated.
	if ms.Value() != "TCP,UDP" {
		t.Fatalf("Value() = %q, want %q", ms.Value(), "TCP,UDP")
	}
	// Toggle TCP off.
	updated, _ = ms.Update(tea.KeyMsg{Type: tea.KeyUp})
	ms = updated.(MultiSelectField)
	updated, _ = ms.Update(tea.KeyMsg{Type: tea.KeySpace})
	ms = updated.(MultiSelectField)
	if ms.Value() != "UDP" {
		t.Fatalf("Value() = %q, want %q", ms.Value(), "UDP")
	}
}

func TestFormFieldPortListField(t *testing.T) {
	t.Parallel()

	pl := NewPortListField("Ports", "TCP/8080", "port specs")
	pl = pl.Focus().(PortListField)
	// Type a spec and press enter.
	updated, _ := pl.Update(keyMsg("TCP/8080"))
	pl = updated.(PortListField)
	updated, _ = pl.Update(tea.KeyMsg{Type: tea.KeyEnter})
	pl = updated.(PortListField)
	if pl.Value() != "TCP/8080" {
		t.Fatalf("Value() = %q, want %q", pl.Value(), "TCP/8080")
	}
	// Add a second spec.
	updated, _ = pl.Update(keyMsg("UDP/53"))
	pl = updated.(PortListField)
	updated, _ = pl.Update(tea.KeyMsg{Type: tea.KeyEnter})
	pl = updated.(PortListField)
	if pl.Value() != "TCP/8080;UDP/53" {
		t.Fatalf("Value() = %q, want %q", pl.Value(), "TCP/8080;UDP/53")
	}
	// Backspace on empty input removes last spec.
	updated, _ = pl.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	pl = updated.(PortListField)
	if pl.Value() != "TCP/8080" {
		t.Fatalf("Value() after backspace = %q, want %q", pl.Value(), "TCP/8080")
	}
}

func TestFormFieldYAMLField(t *testing.T) {
	t.Parallel()

	yf := NewYAMLField("Manifest", "yaml content")
	yf = yf.Focus().(YAMLField)
	if !yf.collapsed {
		t.Fatal("YAMLField should start collapsed")
	}
	var cmd tea.Cmd
	yfResult, _ := yf.Update(tea.KeyMsg{Type: tea.KeyEnter})
	yf = yfResult.(YAMLField)
	_ = cmd
	if yf.collapsed {
		t.Fatal("Enter should expand YAMLField")
	}
	updated, _ := yf.Update(keyMsg("a"))
	yf = updated.(YAMLField)
	if yf.Value() != "a" {
		t.Fatalf("Value() = %q, want %q", yf.Value(), "a")
	}
	view := yf.View()
	if !strings.Contains(view, "Manifest:") {
		t.Fatalf("View() = %q, want label", view)
	}
	yf = yf.Blur().(YAMLField)
	updated, _ = yf.Update(keyMsg("b"))
	yf = updated.(YAMLField)
	if yf.Value() != "a" {
		t.Fatalf("Value() while blurred = %q, want %q", yf.Value(), "a")
	}
}

func TestFormFocusCycling(t *testing.T) {
	t.Parallel()

	form := NewForm(
		NewTextField("A", "", "first"),
		NewBoolField("B", "second"),
		NewNumberField("C", "", "third"),
	)
	if form.FocusedIndex() != 0 {
		t.Fatalf("FocusedIndex() = %d, want 0", form.FocusedIndex())
	}
	if !form.FocusedField().Focused() {
		t.Fatal("focused field should report focused")
	}

	// Down cycles forward.
	form, _ = form.Update(tea.KeyMsg{Type: tea.KeyDown})
	if form.FocusedIndex() != 1 {
		t.Fatalf("after down FocusedIndex() = %d, want 1", form.FocusedIndex())
	}
	form, _ = form.Update(tea.KeyMsg{Type: tea.KeyDown})
	if form.FocusedIndex() != 2 {
		t.Fatalf("after down FocusedIndex() = %d, want 2", form.FocusedIndex())
	}
	// Wrap around.
	form, _ = form.Update(tea.KeyMsg{Type: tea.KeyDown})
	if form.FocusedIndex() != 0 {
		t.Fatalf("after wrap FocusedIndex() = %d, want 0", form.FocusedIndex())
	}
	// Up cycles backward (from 0 to 2).
	form, _ = form.Update(tea.KeyMsg{Type: tea.KeyUp})
	if form.FocusedIndex() != 2 {
		t.Fatalf("after up FocusedIndex() = %d, want 2", form.FocusedIndex())
	}

	// Only one field is focused at a time.
	focusedCount := 0
	for _, f := range []FormField{
		form.fields[0], form.fields[1], form.fields[2],
	} {
		if f.Focused() {
			focusedCount++
		}
	}
	if focusedCount != 1 {
		t.Fatalf("focused field count = %d, want 1", focusedCount)
	}
}

func TestFormViewAndValues(t *testing.T) {
	t.Parallel()

	form := NewForm(
		NewTextField("Source", "", "src workload"),
		NewBoolField("DefaultDeny", "deny all"),
		NewMultiSelectField("Protocols", []string{"TCP", "UDP"}, "protocols"),
	)
	view := form.View()
	for _, label := range []string{"Source", "DefaultDeny", "Protocols"} {
		if !strings.Contains(view, label) {
			t.Fatalf("View() = %q, want it to contain %q", view, label)
		}
	}

	// Set a value on the text field and verify Values().
	tf := form.fields[0].(TextField).Focus().(TextField)
	tf, _ = func() (TextField, tea.Cmd) { u, c := tf.Update(keyMsg("default/frontend")); return u.(TextField), c }()
	form.fields[0] = tf

	// Toggle the bool field.
	bf := form.fields[1].(BoolField).Focus().(BoolField)
	bf, _ = func() (BoolField, tea.Cmd) {
		u, c := bf.Update(tea.KeyMsg{Type: tea.KeySpace})
		return u.(BoolField), c
	}()
	form.fields[1] = bf

	// Select TCP in the multiselect.
	ms := form.fields[2].(MultiSelectField).Focus().(MultiSelectField)
	ms, _ = func() (MultiSelectField, tea.Cmd) {
		u, c := ms.Update(tea.KeyMsg{Type: tea.KeySpace})
		return u.(MultiSelectField), c
	}()
	form.fields[2] = ms

	values := form.Values()
	if values["Source"] != "default/frontend" {
		t.Fatalf("Values()[Source] = %q, want %q", values["Source"], "default/frontend")
	}
	if values["DefaultDeny"] != "true" {
		t.Fatalf("Values()[DefaultDeny] = %q, want %q", values["DefaultDeny"], "true")
	}
	if values["Protocols"] != "TCP" {
		t.Fatalf("Values()[Protocols] = %q, want %q", values["Protocols"], "TCP")
	}
}

func TestFormSetFocus(t *testing.T) {
	t.Parallel()

	form := NewForm(
		NewTextField("A", "", "first"),
		NewTextField("B", "", "second"),
	)
	// NewForm focuses index 0; SetFocus(1) should move it.
	form = form.SetFocus(1)
	if form.FocusedIndex() != 1 {
		t.Fatalf("FocusedIndex() = %d, want 1", form.FocusedIndex())
	}
	if !form.fields[1].Focused() {
		t.Fatal("field 1 should be focused")
	}
	if form.fields[0].Focused() {
		t.Fatal("field 0 should be blurred")
	}
	// Out-of-range SetFocus is a no-op.
	form = form.SetFocus(99)
	if form.FocusedIndex() != 1 {
		t.Fatalf("FocusedIndex() after OOB = %d, want 1", form.FocusedIndex())
	}
}
