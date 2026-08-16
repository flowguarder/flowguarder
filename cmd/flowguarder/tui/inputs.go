package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Field indices for focus management.
const (
	focusSrc = iota
	focusDst
	focusPort
	focusProto
	focusL7Name
	focusL7Pattern
	focusEval  // Evaluate button (always visible)
	focusCount // total number of focusable fields
)

// initInputs initializes the text input fields.
func (m *Model) initInputs() {
	m.portInput = textinput.New()
	m.portInput.Placeholder = "e.g. 8080"
	m.portInput.CharLimit = 5
	m.portInput.Width = 8

	m.protoInput = textinput.New()
	m.protoInput.Placeholder = "TCP"
	m.protoInput.CharLimit = 10
	m.protoInput.Width = 8
	m.protoInput.SetValue("TCP")

	m.l7NameInput = textinput.New()
	m.l7NameInput.Placeholder = "HTTP, DNS, etc."
	m.l7NameInput.CharLimit = 20
	m.l7NameInput.Width = 16

	m.l7PatternInput = textinput.New()
	m.l7PatternInput.Placeholder = "regex pattern"
	m.l7PatternInput.CharLimit = 50
	m.l7PatternInput.Width = 30
}

// setFocus sets the focus to the given field index and updates which inputs are focused.
func (m *Model) setFocus(f int) {
	if f < 0 {
		f = focusCount - 1
	} else if f >= focusCount {
		f = 0
	}
	m.focusField_ = f

	// When focus moves to a list, position its cursor at the first item to
	// give visible highlight feedback.
	if f == focusSrc && m.srcListInit && len(m.srcList.Items()) > 0 {
		m.srcList.Select(0)
	}
	if f == focusDst && m.dstListInit && len(m.dstList.Items()) > 0 {
		m.dstList.Select(0)
	}

	// Blur all text inputs
	m.portInput.Blur()
	m.protoInput.Blur()
	m.l7NameInput.Blur()
	m.l7PatternInput.Blur()

	// Focus the active one
	switch f {
	case focusPort:
		m.portInput.Focus()
	case focusProto:
		m.protoInput.Focus()
	case focusL7Name:
		m.l7NameInput.Focus()
	case focusL7Pattern:
		m.l7PatternInput.Focus()
	}
}

// updateInputs updates the focused text input.
func (m Model) updateInputs(msg tea.Msg) (Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.focusField_ {
	case focusPort:
		m.portInput, cmd = m.portInput.Update(msg)
	case focusProto:
		m.protoInput, cmd = m.protoInput.Update(msg)
	case focusL7Name:
		m.l7NameInput, cmd = m.l7NameInput.Update(msg)
	case focusL7Pattern:
		m.l7PatternInput, cmd = m.l7PatternInput.Update(msg)
	}
	return m, cmd
}

// inputView returns the view for the traffic input fields section.
func (m Model) inputView() string {
	var s strings.Builder

	s.WriteString("\n--- Traffic Inputs ---\n")

	f := lipgloss.Color("63") // K8s blue focus indicator

	// Port
	if m.focusField_ == focusPort {
		s.WriteString(lipgloss.NewStyle().Foreground(f).Render("> "))
	} else {
		s.WriteString("  ")
	}
	s.WriteString("Port: ")
	s.WriteString(m.portInput.View())
	s.WriteString("\n")

	// Protocol
	if m.focusField_ == focusProto {
		s.WriteString(lipgloss.NewStyle().Foreground(f).Render("> "))
	} else {
		s.WriteString("  ")
	}
	s.WriteString("Proto: ")
	s.WriteString(m.protoInput.View())
	s.WriteString("\n")

	// L7 name
	if m.focusField_ == focusL7Name {
		s.WriteString(lipgloss.NewStyle().Foreground(f).Render("> "))
	} else {
		s.WriteString("  ")
	}
	s.WriteString("L7 Name: ")
	s.WriteString(m.l7NameInput.View())
	s.WriteString("\n")

	// L7 pattern
	if m.focusField_ == focusL7Pattern {
		s.WriteString(lipgloss.NewStyle().Foreground(f).Render("> "))
	} else {
		s.WriteString("  ")
	}
	s.WriteString("L7 Pattern: ")
	s.WriteString(m.l7PatternInput.View())
	s.WriteString("\n")

	// Evaluate button — K8s blue background on focus, colored text when idle
	if m.focusField_ == focusEval {
		btn := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("63")).
			Padding(0, 3)
		s.WriteString(" " + btn.Render("Evaluate ▶ "))
	} else {
		btn := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("63")).
			Padding(0, 3)
		s.WriteString(" " + btn.Render("Evaluate ▶ "))
	}
	s.WriteString("\n")

	return s.String()
}
