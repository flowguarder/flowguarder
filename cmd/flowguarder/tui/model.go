// Package tui provides an interactive terminal UI for flowguarder simulate.
package tui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/flowguarder/flowguarder/pkg/simulate"
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

	// Focus management
	focusField_ int // current focusable field (see inputs.go constants)

	// Input fields
	portInput      textinput.Model
	protoInput     textinput.Model
	l7NameInput    textinput.Model
	l7PatternInput textinput.Model
}

// Compile-time check: Model implements tea.Model.
var _ tea.Model = Model{}

// Init initializes the model. Returns nil (no initial command).
func (m Model) Init() tea.Cmd {
	return nil
}

// Update processes messages and returns the updated model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.srcListInit || m.dstListInit {
			listWidth := m.width / 2
			width := listWidth
			if width < 20 {
				width = 20
			}
			listHeight := m.height - 8
			if listHeight > 20 {
				listHeight = 20
			}
			if listHeight < 4 {
				listHeight = 4
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

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab":
			switch m.focusField_ {
			case focusSrc:
				m.setFocus(focusDst)
			case focusDst:
				m.setFocus(focusPort)
			case focusPort, focusProto, focusL7Name, focusL7Pattern:
				m.setFocus(focusEval)
			case focusEval:
				m.setFocus(focusSrc)
			}
			return m, nil
		}

		if m.focusField_ == focusEval && msg.String() == "enter" {
			return m, m.evaluate()
		}

		if m.focusField_ == focusSrc && m.srcListInit {
			if msg.String() == "enter" {
				if idx := m.srcList.Index(); idx >= 0 {
					items := m.srcList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							m.srcItem = item
							m.srcSelected = true
						}
					}
				}
				m.setFocus(focusDst)
				return m, nil
			}
			srcList, cmd := m.srcList.Update(msg)
			m.srcList = srcList
			return m, cmd
		}

		if m.focusField_ == focusDst && m.dstListInit {
			if msg.String() == "enter" {
				if idx := m.dstList.Index(); idx >= 0 {
					items := m.dstList.Items()
					if idx < len(items) {
						if item, ok := items[idx].(selectableItem); ok {
							m.dstItem = item
							m.dstSelected = true
						}
					}
				}
				m.setFocus(focusPort)
				return m, nil
			}
			dstList, cmd := m.dstList.Update(msg)
			m.dstList = dstList
			return m, cmd
		}

		if m.focusField_ == focusPort || m.focusField_ == focusProto ||
			m.focusField_ == focusL7Name || m.focusField_ == focusL7Pattern ||
			m.focusField_ == focusEval {
			switch msg.String() {
			case "up", "k":
				m.setFocus(m.focusField_ - 1)
				return m, nil
			case "down", "j":
				m.setFocus(m.focusField_ + 1)
				return m, nil
			}
		}
	}

	// Delegate to focused text input (not a list).
	var cmd tea.Cmd
	m, cmd = m.updateInputs(msg)
	return m, cmd
}

// View returns the TUI view string.
func (m Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	// Header bar: "flowGuarder Simulate  |  <N> objects  |  <dir basename>"
	var header string
	objCount := 0
	if m.srcListInit {
		objCount = len(m.srcList.Items())
	}
	dirName := filepath.Base(m.policyDir)
	if dirName == "" || dirName == "." {
		dirName = m.policyDir
	}
	headerBgStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("130")).
		Padding(0, 1)
	headerSepStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))
	header = headerBgStyle.Render("flowGuarder Simulate") +
		headerSepStyle.Render(" | ") +
		headerBgStyle.Render(fmt.Sprintf("%d objects", objCount)) +
		headerSepStyle.Render(" | ") +
		headerBgStyle.Render(dirName)

	listWidth := m.width / 2

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

	sep := lipgloss.NewStyle().Foreground(lipgloss.Color("63")).Render(strings.Repeat("─", m.width))
	return header + "\n" + sep + "\n" + top + "\n" + m.inputView() + "\n" + m.resultView()
}

// InitModel initializes the list state for the given selectable objects.
func (m *Model) InitModel(objects SelectableObjects, policyDir string, policies []simulate.LoadedPolicy) {
	m.objects = objects
	m.policyDir = policyDir
	m.policies = policies
	m.srcList = newList(buildSrcItems(objects), "Source Pickers")
	m.dstList = newList(buildDstItems(objects), "Destination Pickers")
	m.focusList = 0
	m.focusField_ = focusSrc
	m.initInputs()
	m.srcListInit = true
	m.dstListInit = true
	if len(m.srcList.Items()) > 0 {
		m.srcList.Select(0)
	}
	if len(m.dstList.Items()) > 0 {
		m.dstList.Select(0)
	}
}

// Run creates a new Model with the given selectable objects and runs the Bubble Tea program
// in alternate screen mode (full terminal).
func Run(objects SelectableObjects, policyDir string, policies []simulate.LoadedPolicy) error {
	m := Model{
		focusList: 0,
	}
	m.InitModel(objects, policyDir, policies)

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
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
