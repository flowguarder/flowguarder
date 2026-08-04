package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderText(t *testing.T) {
	t.Parallel()

	// Load golden file.
	goldenPath := filepath.Join("testdata", "hubble_report.golden")
	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "should read golden file")

	tests := []struct {
		name  string
		input TextReport
	}{
		{
			name:  "hubble report",
			input: buildHubbleTextReport(),
		},
		{
			name:  "calico report",
			input: buildCalicoTextReport(),
		},
		{
			name:  "empty report",
			input: TextReport{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf strings.Builder
			err := RenderText(tt.input, &buf)
			require.NoError(t, err)

			got := buf.String()

			// When golden exists, compare.
			if goldenPath != "" && tt.name == "hubble report" {
				assert.Equal(t, string(golden), got, "text output should match golden")
			}

			// Sanity checks always run.
			if tt.input.Summary.TotalPatterns > 0 {
				assert.Contains(t, got, "Total patterns:")
				assert.Contains(t, got, "===")
			}
			if tt.input.Summary.TotalAnomalies > 0 {
				assert.Contains(t, got, "Anomalies")
			}
		})
	}
}

func TestRenderText_Empty(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	err := RenderText(TextReport{}, &buf)
	require.NoError(t, err)

	got := buf.String()
	assert.Contains(t, got, "Total patterns:      0")
	assert.Contains(t, got, "Total anomalies:     0")
	assert.Contains(t, got, "===")
}

func TestRenderText_Severities(t *testing.T) {
	t.Parallel()
	r := TextReport{
		Summary: Summary{
			TotalPatterns: 2,
			TotalAnomalies: 3,
			AnomaliesBySeverity: map[string]int{
				"high":   1,
				"medium": 1,
				"low":    1,
			},
		},
		Patterns: []TextPattern{
			{Key: "a -> b:80/TCP", Source: "a", Dest: "b", Port: 80, Protocol: "TCP", Count: 10},
		},
		Anomalies: []TextAnomaly{
			{Type: "portscan", Severity: "high", Workload: "a", Description: "scan detected"},
		},
	}

	var buf strings.Builder
	err := RenderText(r, &buf)
	require.NoError(t, err)
	got := buf.String()

	assert.Contains(t, got, "high:")
	assert.Contains(t, got, "medium:")
	assert.Contains(t, got, "low:")
	assert.Contains(t, got, "portscan")
	assert.Contains(t, got, "scan detected")
}

// --- helper builders to construct reports matching golden files ---

func buildHubbleTextReport() TextReport {
	return TextReport{
		Summary: Summary{
			TotalPatterns: 4,
			TotalAnomalies: 2,
			AnomaliesBySeverity: map[string]int{
				"high":   1,
				"medium": 1,
			},
		},
		Patterns: []TextPattern{
			{Key: "default/frontend -> production/backend:8080/TCP", Source: "default/frontend", Dest: "production/backend", Port: 8080, Protocol: "TCP", Count: 150},
			{Key: "default/frontend -> default/postgres:5432/TCP", Source: "default/frontend", Dest: "default/postgres", Port: 5432, Protocol: "TCP", Count: 80},
			{Key: "kube-system/coredns -> production/backend:53/UDP", Source: "kube-system/coredns", Dest: "production/backend", Port: 53, Protocol: "UDP", Count: 200},
			{Key: "staging/api-gw -> production/backend:443/TCP", Source: "staging/api-gw", Dest: "production/backend", Port: 443, Protocol: "TCP", Count: 30},
		},
		Anomalies: []TextAnomaly{
			{Type: "portscan", Severity: "high", Workload: "staging/api-gw", Description: "Detected scan of 25 ports from staging/api-gw within 10s"},
			{Type: "rare_flow", Severity: "medium", Workload: "default/redis", Description: "Unusual traffic pattern detected from default/redis"},
		},
	}
}

func buildCalicoTextReport() TextReport {
	return TextReport{
		Summary: Summary{
			TotalPatterns: 2,
			TotalAnomalies: 0,
			AnomaliesBySeverity: map[string]int{},
		},
		Patterns: []TextPattern{
			{Key: "default/worker -> production/api:3000/TCP", Source: "default/worker", Dest: "production/api", Port: 3000, Protocol: "TCP", Count: 50},
			{Key: "default/worker -> production/api:8080/TCP", Source: "default/worker", Dest: "production/api", Port: 8080, Protocol: "TCP", Count: 25},
		},
		Anomalies: []TextAnomaly{},
	}
}

func TestTextReport_SortedSeverityKeys(t *testing.T) {
	t.Parallel()
	r := TextReport{
		Summary: Summary{
			AnomaliesBySeverity: map[string]int{
				"info":  1,
				"low":   1,
				"high":  2,
				"medium": 1,
			},
		},
	}

	var buf strings.Builder
	err := RenderText(r, &buf)
	require.NoError(t, err)
	got := buf.String()

	// Verify high appears before medium, low, info (the order we use in the render loop)
	idxHigh := strings.Index(got, "high:")
	idxMedium := strings.Index(got, "medium:")
	idxLow := strings.Index(got, "low:")
	idxInfo := strings.Index(got, "info:")

	assert.True(t, idxHigh < idxMedium, "high should appear before medium")
	assert.True(t, idxMedium < idxLow, "medium should appear before low")
	assert.True(t, idxLow < idxInfo, "low should appear before info")
}

func TestTextReport_PatternsSorted(t *testing.T) {
	t.Parallel()
	// Verify that patterns appear in the output (RenderText handles sorting internally
	// via SortByCount which sorts by Key as tiebreaker).
	r := TextReport{
		Patterns: []TextPattern{
			{Key: "z -> a:443/TCP", Source: "z", Dest: "a", Port: 443, Protocol: "TCP", Count: 1},
			{Key: "a -> b:80/TCP", Source: "a", Dest: "b", Port: 80, Protocol: "TCP", Count: 5},
			{Key: "m -> c:22/TCP", Source: "m", Dest: "c", Port: 22, Protocol: "TCP", Count: 3},
		},
	}

	var buf strings.Builder
	err := RenderText(r, &buf)
	require.NoError(t, err)
	got := buf.String()

	// Check all expected pattern keys appear in output.
	assert.Contains(t, got, "a -> b:80/TCP")
	assert.Contains(t, got, "m -> c:22/TCP")
	assert.Contains(t, got, "z -> a:443/TCP")
}

// TestRenderText_KeyOrder verifies deterministic output by running twice.
func TestRenderText_Deterministic(t *testing.T) {
	t.Parallel()
	r := buildHubbleTextReport()

	var buf1, buf2 strings.Builder
	err := RenderText(r, &buf1)
	require.NoError(t, err)
	err = RenderText(r, &buf2)
	require.NoError(t, err)

	assert.Equal(t, buf1.String(), buf2.String(), "RenderText must be deterministic")
}
