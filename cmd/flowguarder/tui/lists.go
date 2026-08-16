package tui

import (
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
)

// selectableItem wraps a display string for the list.
type selectableItem struct {
	title       string
	description string
}

func (i selectableItem) Title() string       { return i.title }
func (i selectableItem) Description() string { return i.description }
func (i selectableItem) FilterValue() string { return i.title }

// formatLabels formats a label map as "key=value, key=value" in sorted order.
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(labels))
	for k, v := range labels {
		pairs = append(pairs, k+"="+v)
	}
	slices.Sort(pairs)
	return strings.Join(pairs, ", ")
}

// buildWorkloadItems creates list items from SelectableWorkload slice.
func buildWorkloadItems(workloads []SelectableWorkload) []list.Item {
	items := make([]list.Item, 0, len(workloads))
	for _, w := range workloads {
		items = append(items, selectableItem{
			title:       w.Namespace + "/" + w.Name,
			description: formatLabels(w.Labels),
		})
	}
	return items
}

// buildEntityItems creates list items from entity strings.
func buildEntityItems(entities []string) []list.Item {
	items := make([]list.Item, 0, len(entities))
	for _, e := range entities {
		items = append(items, selectableItem{
			title:       "entity:" + e,
			description: "Cilium reserved entity",
		})
	}
	return items
}

// buildCIDRItems creates list items from SelectableCIDR slice.
func buildCIDRItems(cidrs []SelectableCIDR) []list.Item {
	items := make([]list.Item, 0, len(cidrs))
	for _, c := range cidrs {
		desc := "CIDR range"
		if c.Desc != "" {
			desc = c.Desc
		}
		items = append(items, selectableItem{
			title:       c.CIDR,
			description: desc,
		})
	}
	return items
}

// buildSrcItems merges workload, entity, and CIDR items for the source picker.
func buildSrcItems(objects SelectableObjects) []list.Item {
	items := make([]list.Item, 0)
	items = append(items, buildWorkloadItems(objects.Workloads)...)
	items = append(items, buildEntityItems(objects.Entities)...)
	items = append(items, buildCIDRItems(objects.CIDRs)...)
	return items
}

// buildDstItems is identical to buildSrcItems (same objects for both sides).
func buildDstItems(objects SelectableObjects) []list.Item {
	return buildSrcItems(objects)
}

// newList creates a styled list.Model with delegate and settings.
func newList(items []list.Item, title string) list.Model {
	const listHeight = 12
	l := list.New(items, newListDelegate(), 0, listHeight)
	l.Title = title
	l.SetFilteringEnabled(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.Styles.Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("63"))
	return l
}

func newListDelegate() list.ItemDelegate {
	d := list.NewDefaultDelegate()
	d.Styles.SelectedTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Bold(true)
	d.Styles.NormalTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("252"))
	return d
}
