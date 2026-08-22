package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// sectionTitle renders a section heading with the app-wide focus language:
// focused titles get the white-on-K8s-blue badge used by the header and the
// Output pane; unfocused titles are dimmed. Padding keeps every variant on a
// single line without changing line counts.
func sectionTitle(focused bool, text string) string {
	if focused {
		return lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("63")).
			Padding(0, 1).
			Render(text)
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render(text)
}

// reportsBottomGap is the number of blank rows kept between the reports
// block and the bottom of the left column in every tab.
const reportsBottomGap = 3

// pinReportsLeft appends the reports group to the left column so it starts
// on body row bodyH-reportLines-reportsBottomGap+1, regardless of what sits
// above. Both the Analyze and Live tabs use it, which guarantees the group
// renders at the same height in every tab and never moves when the source
// widget above renders fewer or more lines than requested.
func pinReportsLeft(left *strings.Builder, reportsView string, reportLines, bodyH int) {
	if !strings.HasSuffix(left.String(), "\n") {
		left.WriteString("\n")
	}
	completedRows := strings.Count(left.String(), "\n")
	pad := bodyH - reportLines - completedRows - reportsBottomGap
	if pad < 0 {
		pad = 0
	}
	left.WriteString(strings.Repeat("\n", pad))
	left.WriteString(reportsView)
}
