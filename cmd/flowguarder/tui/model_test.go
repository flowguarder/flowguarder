package tui

import (
	"testing"

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
