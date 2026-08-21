package tui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// NewAnalyzeTab constructs the Analyze tab state: a file picker for the flow
// source path (file or directory, no extension filter) and a scrollable form
// of every analyze CLI flag plus config key. The file picker holds focus first.
func NewAnalyzeTab() AnalyzeTab {
	picker := filepicker.New()
	picker.DirAllowed = true
	picker.FileAllowed = true
	picker.AllowedTypes = nil
	picker.AutoHeight = false
	picker.SetHeight(12)
	picker.CurrentDirectory = "."
	picker.Path = "."

	fields := []FormField{
		// --- Analyze CLI flags (source handled by the picker) ---
		NewTextField("--output", "policies", "Output directory for policy YAML manifests"),
		NewSelectField("--format", []string{"text", "json", "both"}, "text", "Report output format: text, json, both"),
		NewBoolField("--strict", "Disable safety margins for policy generation"),
		NewBoolField("--default-deny", "Add deny-all stub policies"),
		NewSelectField("--policy-format", []string{"auto", "np", "cnp"}, "auto", "Policy output format: auto, np, cnp"),
		NewBoolField("--cilium", "Legacy alias for --policy-format=cnp"),
		NewNumberField("--top-n", "10", "Number of top entries in reports"),
		NewBoolField("--generate-uncovered", "Generate policies for uncovered traffic"),
		NewBoolField("--skip-visualize", "Skip generating the visualization HTML"),

		// --- Config scalar / list options ---
		NewTextField("cluster_cidrs", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fd00::/8, 100.64.0.0/10", "IP ranges considered internal (RFC 1918 + CGNAT + ULA), comma-separated"),
		NewTextField("excluded_namespaces", "kube-system, calico-system, tigera-operator", "Namespaces whose flows are ignored, comma-separated"),
		NewPortListField("kube_dns_ports", "UDP/53", "Well-known Kubernetes DNS ports"),
		NewNumberField("rare_flow_threshold", "0.001", "Percentile (0..1) below which a pattern is rare"),
		NewNumberField("port_scan_threshold", "10", "Distinct ports within window before flagging"),
		NewNumberField("port_scan_window_seconds", "10", "Time window for port-scan detection"),
		NewNumberField("asymmetric_ratio", "10", "Egress/ingress byte ratio threshold"),
		NewTextField("public_egress_known_good", "docker.io, ghcr.io, gcr.io, k8s.gcr.io", "Domain names known-good as legitimate egress targets, comma-separated"),
		NewTextField("known_good_external_endpoints", "pypi.org, registry.npmjs.org, apt.ubuntu.com", "FQDNs or IPs confirmed-good external egress targets, comma-separated"),
		NewTextField("public_egress_allowlist_cidrs", "", "Public CIDR ranges considered benign (comma-separated)"),
		NewPortListField("apiserver_ingress_ports", "TCP/9443", "Well-known ingress ports for kube-apiserver"),
		NewPortListField("apiserver_egress_ports", "TCP/6443", "Well-known egress ports to kube-apiserver"),
		NewTextField("node_cidrs", "", "Optional IP ranges covering cluster nodes (comma-separated)"),
		NewBoolField("always_allow_dns", "Synthesize an egress rule (UDP+TCP 53 to kube-dns) for every workload"),

		// --- Complex nested config (YAML textareas) ---
		NewYAMLField("allowed_namespace_pairs", "Maps source namespace to allowed destination namespaces"),
		NewYAMLField("per_namespace_profiles", "Per-namespace rules: allowed_targets, disallowed_targets, required_labels"),
		NewYAMLField("public_services", "Kubernetes services rendered as a single match-all ingress rule"),
		NewYAMLField("apiserver_workload_selector", "Identifies the workload treated as kube-apiserver"),
	}

	form := NewForm(fields...)
	form.setFieldValue("--policy-format", "auto")
	// Blur every field initially so only the file picker shows a focus marker.
	for i := range form.fields {
		form.fields[i] = form.fields[i].Blur()
	}
	form.focusIndex = -1

	return AnalyzeTab{
		picker:        picker,
		form:          form,
		pickerFocused: true,
	}
}

// renderAnalyzeBody renders the Analyze tab using a two-column layout:
// LEFT column = file picker + reports section; RIGHT column = scrollable options form.
func (m Model) renderAnalyzeBody() string {
	var left strings.Builder
	left.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render("Select flow source:"))
	left.WriteString("\n")
	src := m.analyzeTab.picker.Path
	if src == "" {
		src = "(none selected)"
	}
	left.WriteString("  Source: ")
	left.WriteString(src)
	left.WriteString("\n")
	pickerView := m.analyzeTab.picker.View()
	if m.analyzeTab.picker.CurrentDirectory != "/" && m.analyzeTab.picker.CurrentDirectory != "." && m.analyzeTab.pickerCursorPos == 0 {
		lines := strings.SplitN(pickerView, "\n", 2)
		if len(lines) > 1 {
			left.WriteString("> ..\n")
			line0 := stripFilePickerCursor(lines[0])
			left.WriteString("  " + line0 + "\n")
			left.WriteString(lines[1])
		} else {
			left.WriteString("> ..\n")
		}
	} else if m.analyzeTab.picker.CurrentDirectory != "/" && m.analyzeTab.picker.CurrentDirectory != "." {
		left.WriteString("  ..\n")
		left.WriteString(pickerView)
	} else {
		left.WriteString(pickerView)
	}
	left.WriteString("\n\n")
	left.WriteString(m.renderAnalyzeReports())

	leftWidth := m.width / 2
	rightWidth := m.width - leftWidth
	bodyH := m.height - 5 - m.bottomViewportHeight()
	if bodyH < 5 {
		bodyH = 5
	}
	pickerH := bodyH - 4
	if pickerH < 3 {
		pickerH = 3
	}
	m.analyzeTab.picker.SetHeight(pickerH)

	var right strings.Builder
	right.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render("Options:"))
	right.WriteString("\n")
	right.WriteString(m.analyzeTab.form.View())

	// Run button at bottom of Options column (matching Live tab layout).
	right.WriteString("\n\n")
	runFocused := m.activeArea == AreaAnalyzeRun
	runPrefix := "  "
	if runFocused {
		runPrefix = lipgloss.NewStyle().Foreground(lipgloss.Color("63")).Render("> ")
	}
	right.WriteString("    ")
	right.WriteString(runPrefix)
	if m.analyzeRunning {
		right.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Running… ▶"))
	} else {
		right.WriteString(m.analyzeRunButton.View(runFocused))
	}
	right.WriteString("\n")

	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(leftWidth).Render(left.String()),
		lipgloss.NewStyle().Width(rightWidth).Render(right.String()),
	)
}

// Values returns the current analyze option values keyed by field label,
// including the selected source path under "Source". This round-trips every
// analyze CLI flag and config key exposed by the form.
func (at AnalyzeTab) Values() map[string]string {
	v := at.form.Values()
	v["Source"] = at.picker.Path
	return v
}

// updateAnalyze handles messages while the Analyze tab is active. Tab and
// Shift+Tab are handled by the top-level Model (they switch tabs or move
// between form/reports); all other keys are routed here. The file picker holds
// focus first; selecting a file (enter) moves focus to the options form, and
// esc returns focus to the picker. This mirrors the Live tab's focus model.
func (m Model) updateAnalyze(msg tea.Msg) (Model, tea.Cmd) {
	if m.analyzeTab.pickerFocused {
		// When on the synthetic ".." entry, handle navigation ourselves and
		// prevent the Bubbles picker from moving its internal cursor. This
		// keeps our synthetic cursor in sync: cursorPos==0 → "..", picker
		// cursor at 0; cursorPos==1 → first file, picker cursor still at 0.
		if m.analyzeTab.pickerCursorPos == 0 {
			if key, ok := msg.(tea.KeyMsg); ok {
				switch key.String() {
				case "down", "j", "ctrl+n":
					m.analyzeTab.pickerCursorPos++
					return m, nil
				case "up", "k", "ctrl+p", "pgup", "pgdown", "g", "K":
					return m, nil
				}
			}
		}

		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "up", "k", "ctrl+p":
				if m.analyzeTab.pickerCursorPos > 0 {
					m.analyzeTab.pickerCursorPos--
				}
			case "down", "j", "ctrl+n":
				m.analyzeTab.pickerCursorPos++
			case "g":
				m.analyzeTab.pickerCursorPos = 0
			case "pgup", "K":
				m.analyzeTab.pickerCursorPos = 0
			case "enter":
				if m.analyzeTab.pickerCursorPos == 0 {
					parent := filepath.Dir(m.analyzeTab.picker.CurrentDirectory)
					if parent != m.analyzeTab.picker.CurrentDirectory {
						m.analyzeTab.picker.CurrentDirectory = parent
						m.analyzeTab.picker.Path = ""
						m.analyzeTab.pickerCursorPos = 0
						return m, m.analyzeTab.picker.Init()
					}
				}
			}
		}

		oldDir := m.analyzeTab.picker.CurrentDirectory
		picker, cmd := m.analyzeTab.picker.Update(msg)
		m.analyzeTab.picker = picker
		if picker.CurrentDirectory != oldDir {
			m.analyzeTab.pickerCursorPos = 0
		}
		// Selecting a file hands focus to the options form.
		if didSelect, path := picker.DidSelectFile(msg); didSelect {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				m.analyzeTab.pickerFocused = false
				m.analyzeTab.form = m.analyzeTab.form.SetFocus(0)
			}
		}
		return m, cmd
	}

	// Run button holds focus.
	if m.activeArea == AreaAnalyzeRun {
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "esc", "up", "k":
				m.activeArea = AreaAnalyzeReports
				m.analyzeReports = m.analyzeReports.Focus().(AnalyzeReports)
				return m, nil
			case "enter":
				return m, m.handleAnalyzeRun()
			}
		}
		return m, nil
	}

	// Reports section holds focus: route keys to AnalyzeReports.
	if m.analyzeReports.Focused() {
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "esc":
				m.analyzeReports = m.analyzeReports.Blur().(AnalyzeReports)
				if len(m.analyzeTab.form.fields) > 0 {
					m.analyzeTab.form = m.analyzeTab.form.SetFocus(len(m.analyzeTab.form.fields) - 1)
				}
				return m, nil
			case "enter":
				// Enter on Run button (when in AreaAnalyzeReports) triggers analyze run.
				return m, m.handleAnalyzeRun()
			}
		}
		updated, cmd := m.analyzeReports.Update(msg)
		m.analyzeReports = updated.(AnalyzeReports)
		return m, cmd
	}

	// Options form holds focus.
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.analyzeTab.pickerFocused = true
			m.analyzeTab.form = blurForm(m.analyzeTab.form)
			return m, nil
		}
	}
	form, cmd := m.analyzeTab.form.Update(msg)
	m.analyzeTab.form = form
	return m, cmd
}

// blurForm blurs whichever field currently holds focus in the form.
func blurForm(f Form) Form {
	idx := f.FocusedIndex()
	if idx >= 0 && idx < len(f.fields) {
		f.fields[idx] = f.fields[idx].Blur()
	}
	f.focusIndex = -1
	return f
}
