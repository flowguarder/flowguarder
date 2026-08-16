package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleAllow        = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))            // green
	styleDeny         = lipgloss.NewStyle().Foreground(lipgloss.Color("41"))            // red
	styleUndetermined = lipgloss.NewStyle().Foreground(lipgloss.Color("228"))           // yellow
	styleError        = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))           // bright red
	styleHeader       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")) // K8s blue
)

// verdictStyle returns the lipgloss style for a verdict string.
func verdictStyle(verdict string) lipgloss.Style {
	switch verdict {
	case "allow":
		return styleAllow
	case "deny":
		return styleDeny
	default:
		return styleUndetermined
	}
}

// resultView renders the verdict and error display pane.
func (m Model) resultView() string {
	var s strings.Builder

	if m.err != nil {
		s.WriteString(styleError.Render("Error: " + m.err.Error()))
		s.WriteString("\n")
		return s.String()
	}

	if m.result == nil {
		s.WriteString("Select source, destination, and press Evaluate\n")
		s.WriteString("Tab: cycle fields · ↑↓: navigate · Enter: select\n")
		return s.String()
	}

	s.WriteString(styleHeader.Render("--- Verdict ---"))
	s.WriteString("\n")

	// Ingress
	ingressStyle := verdictStyle(m.result.Ingress)
	fmt.Fprintf(&s, "Ingress:  %s\n", ingressStyle.Render(m.result.Ingress))

	// Egress
	egressStyle := verdictStyle(m.result.Egress)
	fmt.Fprintf(&s, "Egress:   %s\n", egressStyle.Render(m.result.Egress))

	// Matching files
	if len(m.result.MatchingFiles) > 0 {
		s.WriteString("\n")
		s.WriteString(styleHeader.Render("Matching Files:"))
		s.WriteString("\n")
		for _, f := range m.result.MatchingFiles {
			s.WriteString("  " + f + "\n")
		}
	}

	return s.String()
}
