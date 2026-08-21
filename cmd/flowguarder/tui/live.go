package tui

import (
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// LiveSource identifies which live flow source the Live tab is configured to
// use.
type LiveSource int

const (
	// LiveSourceHubble selects a Hubble Relay gRPC server as the source.
	LiveSourceHubble LiveSource = iota
	// LiveSourceCalico selects a Calico flow log file as the source.
	LiveSourceCalico
)

// LiveSourceSelector is a radio-style selector for the live flow source. It
// implements the FormField interface so it can be composed with the other form
// primitives, though the Live tab manages it directly rather than via a Form.
//
// The selector performs no I/O: it only tracks which source is selected and
// which option the cursor is currently highlighting.
type LiveSourceSelector struct {
	source      LiveSource
	cursor      int // 0 = Hubble server, 1 = Calico file
	focused     bool
	label       string
	description string
}

var _ FormField = (*LiveSourceSelector)(nil)

// NewLiveSourceSelector creates a selector defaulting to the Hubble source.
func NewLiveSourceSelector() LiveSourceSelector {
	return LiveSourceSelector{
		source:      LiveSourceHubble,
		cursor:      0,
		focused:     false,
		label:       "Source",
		description: "Choose the live flow source: a Hubble Relay server or a Calico flow log file.",
	}
}

// Update moves the cursor with up/down and selects the highlighted source with
// space or enter when focused.
func (s LiveSourceSelector) Update(msg tea.Msg) (FormField, tea.Cmd) {
	if !s.focused {
		return s, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	switch key.String() {
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.cursor < 1 {
			s.cursor++
		}
	case " ", "enter":
		if s.cursor == 0 {
			s.source = LiveSourceHubble
		} else {
			s.source = LiveSourceCalico
		}
	}
	return s, nil
}

// View renders the two source options with radio indicators and a cursor.
func (s LiveSourceSelector) View() string {
	var b strings.Builder
	b.WriteString(focusPrefix(s.focused))
	b.WriteString(s.label)
	b.WriteString(":\n")

	opts := []struct {
		src  LiveSource
		name string
	}{
		{LiveSourceHubble, "Hubble server"},
		{LiveSourceCalico, "Calico file"},
	}
	for i, o := range opts {
		mark := " "
		if s.source == o.src {
			mark = "x"
		}
		cursor := " "
		if s.focused && i == s.cursor {
			cursor = ">"
		}
		b.WriteString("    ")
		b.WriteString(cursor)
		b.WriteString(" [")
		b.WriteString(mark)
		b.WriteString("] ")
		b.WriteString(o.name)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// Value returns "hubble" or "calico" for the selected source.
func (s LiveSourceSelector) Value() string {
	if s.source == LiveSourceCalico {
		return "calico"
	}
	return "hubble"
}

// Label returns the field label.
func (s LiveSourceSelector) Label() string { return s.label }

// Description returns the help text.
func (s LiveSourceSelector) Description() string { return s.description }

// Focused reports whether the selector holds focus.
func (s LiveSourceSelector) Focused() bool { return s.focused }

// Focus engages focus on the selector.
func (s LiveSourceSelector) Focus() FormField {
	s.focused = true
	return s
}

// Blur disengages focus on the selector.
func (s LiveSourceSelector) Blur() FormField {
	s.focused = false
	return s
}

// LiveTab holds the Live tab UI state: the source selector plus the
// source-specific input, an options form, and the run button.
//
// It performs no network I/O and never validates server reachability — it is
// purely UI state that the CLI layer consumes when the user starts a live run.
type LiveTab struct {
	selector        LiveSourceSelector
	hubbleAddr      TextField
	calicoFile      filepicker.Model
	focusIndex      int // 0 = source selector, 1 = conditional input, 2 = form, 3 = run button
	runButton       RunButton
	calicoCursorPos int
	form            Form
}

// NewLiveTab creates a LiveTab with the Hubble source selected by default.
// The Calico file picker is initialized so it has a directory listing ready
// when the user switches to the Calico source.
func NewLiveTab() LiveTab {
	fp := filepicker.New()
	fp.AllowedTypes = nil // no extension filter
	fp.DirAllowed = false
	fp.FileAllowed = true
	fp.AutoHeight = false
	fp.SetHeight(10)
	fp.CurrentDirectory = "."
	fp.Path = "."

	// Initialize picker so its item list is populated for View().
	if cmd := fp.Init(); cmd != nil {
		msg := cmd()
		fp, _ = fp.Update(msg)
	}

	form := NewForm(
		NewTextField("--output", "policies", "Output directory for policy YAML manifests"),
		NewSelectField("--format", []string{"text", "json", "both"}, "text", "Report output format: text, json, both"),
		NewBoolField("--strict", "Disable safety margins for policy generation"),
		NewBoolField("--default-deny", "Add deny-all stub policies"),
		NewSelectField("--policy-format", []string{"auto", "np", "cnp"}, "auto", "Policy output format: auto, np, cnp"),
		NewBoolField("--cilium", "Legacy alias for --policy-format=cnp"),
		NewNumberField("--top-n", "10", "Number of top entries in reports"),
		NewBoolField("--generate-uncovered", "Generate policies for uncovered traffic"),
		NewBoolField("--skip-visualize", "Skip generating the visualization HTML"),
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
		NewYAMLField("allowed_namespace_pairs", "Maps source namespace to allowed destination namespaces"),
		NewYAMLField("per_namespace_profiles", "Per-namespace rules: allowed_targets, disallowed_targets, required_labels"),
		NewYAMLField("public_services", "Kubernetes services rendered as a single match-all ingress rule"),
		NewYAMLField("apiserver_workload_selector", "Identifies the workload treated as kube-apiserver"),
	)
	form.setFieldValue("--policy-format", "auto")
	for i := range form.fields {
		form.fields[i] = form.fields[i].Blur()
	}
	form.focusIndex = -1

	return LiveTab{
		selector:   NewLiveSourceSelector(),
		hubbleAddr: NewTextField("Hubble server address", "host:port", "Hubble Relay gRPC server address (host:port)."),
		calicoFile: fp,
		focusIndex: 0,
		runButton:  NewRunButton("Run"),
		form:       form,
	}
}

// Source returns the currently selected live source.
func (t LiveTab) Source() LiveSource { return t.selector.source }

// HubbleAddress returns the current Hubble server address text.
func (t LiveTab) HubbleAddress() string { return t.hubbleAddr.Value() }

// CalicoFilePath returns the currently selected Calico file path.
func (t LiveTab) CalicoFilePath() string { return t.calicoFile.Path }

// Update handles navigation for the Live tab. Tab/Shift+Tab are handled by the
// top-level Model (they switch tabs); all other keys are routed here. Enter or
// space on the selector selects the highlighted source and moves focus to the
// conditional input; arrows navigate the selector options. Pressing esc on the
// conditional input returns focus to the selector.
func (t LiveTab) Update(msg tea.Msg) (LiveTab, tea.Cmd) {
	var cmd tea.Cmd

	if key, ok := msg.(tea.KeyMsg); ok && t.focusIndex == 1 {
		switch key.String() {
		case "esc":
			t.focusIndex = 0
			if t.selector.source == LiveSourceHubble {
				t.hubbleAddr = t.hubbleAddr.Blur().(TextField)
			}
			return t, cmd
		case "down", "j":
			// Only jump to the form (or run button) for Hubble (text input has
			// no further down-navigation). For Calico the filepicker
			// needs down to navigate directories.
			if t.selector.source == LiveSourceHubble {
				t.focusIndex = 2
				t.hubbleAddr = t.hubbleAddr.Blur().(TextField)
				return t, cmd
			}
		}
	}

	if t.focusIndex == 0 {
		t.selector = t.selector.Focus().(LiveSourceSelector)
		updated, _ := t.selector.Update(msg)
		t.selector = updated.(LiveSourceSelector)
		if key, ok := msg.(tea.KeyMsg); ok {
			if key.String() == " " || key.String() == "enter" {
				t.focusIndex = 1
				t.selector = t.selector.Blur().(LiveSourceSelector)
				if t.selector.source == LiveSourceHubble {
					t.hubbleAddr = t.hubbleAddr.Focus().(TextField)
				}
			}
		}
		return t, cmd
	}

	if t.selector.source == LiveSourceHubble {
		if !t.hubbleAddr.Focused() {
			t.hubbleAddr = t.hubbleAddr.Focus().(TextField)
		}
		updated, _ := t.hubbleAddr.Update(msg)
		t.hubbleAddr = updated.(TextField)
	} else {
		// When on the synthetic ".." entry, handle navigation ourselves and
		// prevent the Bubbles picker from moving its internal cursor. This
		// keeps our synthetic cursor in sync: cursorPos==0 → "..", picker
		// cursor at 0; cursorPos==1 → first file, picker cursor still at 0.
		if t.calicoCursorPos == 0 {
			if key, ok := msg.(tea.KeyMsg); ok {
				switch key.String() {
				case "down", "j", "ctrl+n":
					t.calicoCursorPos++
					return t, nil
				case "up", "k", "ctrl+p", "pgup", "pgdown", "g", "K":
					return t, nil
				}
			}
		}

		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "up", "k", "ctrl+p":
				if t.calicoCursorPos > 0 {
					t.calicoCursorPos--
				}
			case "down", "j", "ctrl+n":
				t.calicoCursorPos++
			case "g":
				t.calicoCursorPos = 0
			case "pgup", "K":
				t.calicoCursorPos = 0
			case "enter":
				if t.calicoCursorPos == 0 {
					parent := filepath.Dir(t.calicoFile.CurrentDirectory)
					if parent != t.calicoFile.CurrentDirectory {
						t.calicoFile.CurrentDirectory = parent
						t.calicoFile.Path = ""
						t.calicoCursorPos = 0
						return t, t.calicoFile.Init()
					}
				}
			}
		}

		oldDir := t.calicoFile.CurrentDirectory
		t.calicoFile, cmd = t.calicoFile.Update(msg)
		if t.calicoFile.CurrentDirectory != oldDir {
			t.calicoCursorPos = 0
		}
	}
	return t, cmd
}

func (t LiveTab) renderCalicoPicker() string {
	var b strings.Builder
	pickerView := t.calicoFile.View()
	if t.calicoFile.CurrentDirectory != "/" && t.calicoFile.CurrentDirectory != "." && t.calicoCursorPos == 0 {
		lines := strings.SplitN(pickerView, "\n", 2)
		if len(lines) > 1 {
			b.WriteString("> ..\n")
			line0 := stripFilePickerCursor(lines[0])
			b.WriteString("  " + line0 + "\n")
			b.WriteString(lines[1])
		} else {
			b.WriteString("> ..\n")
		}
	} else if t.calicoFile.CurrentDirectory != "/" && t.calicoFile.CurrentDirectory != "." {
		b.WriteString("  ..\n")
		b.WriteString(pickerView)
	} else {
		b.WriteString(pickerView)
	}
	return b.String()
}

// View renders the source selector followed by the source-specific input. Only
// the input for the selected source is shown; the other is hidden.
func (t LiveTab) View() string {
	var b strings.Builder
	b.WriteString(t.selector.View())
	b.WriteString("\n\n")
	if t.selector.source == LiveSourceHubble {
		b.WriteString(t.hubbleAddr.View())
	} else {
		b.WriteString(t.renderCalicoPicker())
	}
	return b.String()
}

func (t LiveTab) ViewWithState(running bool, width, height int) string {
	bottomH := 5
	if height > 0 {
		avail := height - 14
		if avail > bottomH {
			bottomH = avail / 3
		}
		if bottomH < 3 {
			bottomH = 3
		}
		if bottomH > 12 {
			bottomH = 12
		}
	}
	bodyH := height - 5 - bottomH
	if bodyH < 5 {
		bodyH = 5
	}

	leftWidth := width / 2
	rightWidth := width - leftWidth

	var left strings.Builder
	left.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render("Select flow source:"))
	left.WriteString("\n\n")
	left.WriteString(t.selector.View())
	left.WriteString("\n\n")
	if t.selector.source == LiveSourceHubble {
		left.WriteString(t.hubbleAddr.View())
	} else {
		left.WriteString(t.renderCalicoPicker())
	}

	var right strings.Builder
	right.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render("Options:"))
	right.WriteString("\n")
	right.WriteString(t.form.View())
	right.WriteString("\n\n")

	runPrefix := "  "
	if t.focusIndex == 3 {
		runPrefix = focusPrefix(true)
	}
	right.WriteString("    ")
	right.WriteString(runPrefix)
	if running {
		right.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Running… ▶"))
	} else {
		right.WriteString(t.runButton.View(t.focusIndex == 3))
	}
	right.WriteString("\n")

	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(leftWidth).Render(left.String()),
		lipgloss.NewStyle().Width(rightWidth).Render(right.String()),
	)
}

func (t LiveTab) UpdateWithState(msg tea.Msg, running bool) (LiveTab, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "esc" && t.focusIndex == 2 {
		// ESC from form goes to the input area (focusIndex 1).
		t.focusIndex = 1
		if t.selector.source == LiveSourceHubble {
			t.hubbleAddr = t.hubbleAddr.Focus().(TextField)
		}
		return t, nil
	}
	if t.focusIndex == 2 {
		updated, cmd := t.form.Update(msg)
		t.form = updated
		return t, cmd
	}
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "esc" && t.focusIndex == 3 {
		t.focusIndex = 2
		return t, nil
	}
	return t.Update(msg)
}
