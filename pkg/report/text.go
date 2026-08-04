package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// TextReport holds data rendered by RenderText.
type TextReport struct {
	Summary
	Patterns  []TextPattern
	Anomalies []TextAnomaly
}

// Summary holds aggregate counts for a report.
type Summary struct {
	TotalPatterns       int
	TotalAnomalies      int
	AnomaliesBySeverity map[string]int
}

// TextPattern represents one aggregated traffic pattern for the text report.
type TextPattern struct {
	Key      string
	Source   string
	Dest     string
	Port     uint16
	Protocol string
	Count    uint64
}

// TextAnomaly represents one detected anomaly for the text report.
type TextAnomaly struct {
	Type        string
	Severity    string
	Workload    string
	Description string
}

// RenderText writes a human-readable table to w.
func RenderText(r TextReport, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// --- Summary ---
	fmt.Fprintf(tw, "=== flowGuarder Analysis Report ===\n\n")
	fmt.Fprintf(tw, "Summary\n")
	fmt.Fprintf(tw, "  Total patterns:      %d\n", r.Summary.TotalPatterns)
	fmt.Fprintf(tw, "  Total anomalies:     %d\n", r.Summary.TotalAnomalies)
	if len(r.Summary.AnomaliesBySeverity) > 0 {
		fmt.Fprintf(tw, "  Anomalies by severity:\n")
		for _, sev := range []string{"high", "medium", "low", "info"} {
			c, ok := r.Summary.AnomaliesBySeverity[sev]
			if !ok {
				continue
			}
			fmt.Fprintf(tw, "    %-10s %d\n", sev+":", c)
		}
		fmt.Fprintf(tw, "\n")
	}

	// --- Patterns table ---
	fmt.Fprintf(tw, "Patterns\n")
	fmt.Fprintf(tw, "%s\n", strings.Repeat("-", 80))
	fmt.Fprintf(tw, "%-10s %-10s %-20s %6s  %-6s %12s\n",
		"Source", "Dest", "Key", "Port", "Proto", "Count")
	for _, p := range r.Patterns {
		fmt.Fprintf(tw, "%-10s %-10s %-20s %6d  %-6s %12d\n",
			p.Source,
			p.Dest,
			p.Key,
			p.Port,
			p.Protocol,
			p.Count,
		)
	}
	fmt.Fprintf(tw, "\n")

	// --- Anomalies list ---
	fmt.Fprintf(tw, "Anomalies\n")
	fmt.Fprintf(tw, "%s\n", strings.Repeat("-", 80))
	for _, a := range r.Anomalies {
		fmt.Fprintf(tw, "  [%-6s] %-15s %-20s %s\n",
			a.Severity, a.Type, a.Workload, a.Description)
	}
	fmt.Fprintf(tw, "\n")
	fmt.Fprintf(tw, "====================================\n")

	return tw.Flush()
}
