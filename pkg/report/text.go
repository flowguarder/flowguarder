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
	if _, err := fmt.Fprintf(tw, "=== flowGuarder Analysis Report ===\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "Summary\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "  Total patterns:      %d\n", r.TotalPatterns); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "  Total anomalies:     %d\n", r.TotalAnomalies); err != nil {
		return err
	}
	if len(r.AnomaliesBySeverity) > 0 {
		if _, err := fmt.Fprintf(tw, "  Anomalies by severity:\n"); err != nil {
			return err
		}
		for _, sev := range []string{"high", "medium", "low", "info"} {
			c, ok := r.AnomaliesBySeverity[sev]
			if !ok {
				continue
			}
			if _, err := fmt.Fprintf(tw, "    %-10s %d\n", sev+":", c); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(tw, "\n"); err != nil {
			return err
		}
	}

	// --- Patterns table ---
	if _, err := fmt.Fprintf(tw, "Patterns\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "%s\n", strings.Repeat("-", 80)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "%-10s %-10s %-20s %6s  %-6s %12s\n",
		"Source", "Dest", "Key", "Port", "Proto", "Count"); err != nil {
		return err
	}
	for _, p := range r.Patterns {
		if _, err := fmt.Fprintf(tw, "%-10s %-10s %-20s %6d  %-6s %12d\n",
			p.Source,
			p.Dest,
			p.Key,
			p.Port,
			p.Protocol,
			p.Count,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(tw, "\n"); err != nil {
		return err
	}

	// --- Anomalies list ---
	if _, err := fmt.Fprintf(tw, "Anomalies\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "%s\n", strings.Repeat("-", 80)); err != nil {
		return err
	}
	for _, a := range r.Anomalies {
		if _, err := fmt.Fprintf(tw, "  [%-6s] %-15s %-20s %s\n",
			a.Severity, a.Type, a.Workload, a.Description); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(tw, "\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "====================================\n"); err != nil {
		return err
	}

	return tw.Flush()
}
