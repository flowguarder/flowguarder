package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderJSON(t *testing.T) {
	t.Parallel()

	goldenPath := "testdata/hubble_json.golden"
	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "should read golden file")

	tests := []struct {
		name  string
		input JSONReport
	}{
		{
			name:  "hubble report",
			input: buildHubbleJSONReport(),
		},
		{
			name:  "calico report",
			input: buildCalicoJSONReport(),
		},
		{
			name:  "empty report",
			input: JSONReport{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf strings.Builder
			err := RenderJSON(tt.input, &buf)
			require.NoError(t, err)

			got := strings.TrimSpace(buf.String())

			if tt.name == "hubble report" {
				assert.JSONEq(t, string(golden), got, "json output should match golden")
			}

			// Parse to verify valid JSON.
			var parsed map[string]interface{}
			err = json.Unmarshal([]byte(got), &parsed)
			require.NoError(t, err, "output must be valid JSON")

			// Top-level keys must be present.
			assert.Contains(t, parsed, "summary", "summary key must exist")
			assert.Contains(t, parsed, "patterns", "patterns key must exist")
			assert.Contains(t, parsed, "anomalies", "anomalies key must exist")
		})
	}
}

func TestRenderJSON_Empty(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	err := RenderJSON(JSONReport{}, &buf)
	require.NoError(t, err)

	got := strings.TrimSpace(buf.String())

	// Verify structure.
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(got), &parsed)
	require.NoError(t, err)

	sum := parsed["summary"].(map[string]interface{})
	assert.Equal(t, float64(0), sum["total_patterns"])
	assert.Equal(t, float64(0), sum["total_anomalies"])
}

func TestRenderJSON_SortedKeys(t *testing.T) {
	t.Parallel()
	r := JSONReport{
		Summary: Summary{
			TotalPatterns:       1,
			TotalAnomalies:      1,
			AnomaliesBySeverity: map[string]int{"high": 1, "low": 1, "medium": 1},
		},
		Patterns: []JSONPattern{
			{Key: "test", Src: "s", Dst: "d", Port: 80, Protocol: "TCP", Count: 1},
		},
		Anomalies: []JSONAnomaly{
			{Type: "foo", Severity: "high", Workload: "w", Description: "desc"},
		},
	}

	var buf strings.Builder
	err := RenderJSON(r, &buf)
	require.NoError(t, err)

	// Verify key ordering by checking string positions.
	got := buf.String()

	summary := got
	// At top level: anomalies should come before patterns should come before summary
	// because alphabetical: anomalies < patterns < summary
	idxAnomalies := strings.Index(got, `"anomalies"`)
	idxPatterns := strings.Index(got, `"patterns"`)
	idxSummary := strings.Index(got, `"summary"`)

	assert.True(t, idxAnomalies < idxPatterns, "anomalies key must come before patterns")
	assert.True(t, idxPatterns < idxSummary, "patterns key must come before summary")

	// Within summary: anomalies_by_severity < total_anomalies < total_patterns
	idxAbv := strings.Index(summary, `"anomalies_by_severity"`)
	idxTa := strings.Index(summary, `"total_anomalies"`)
	idxTp := strings.Index(summary, `"total_patterns"`)

	assert.True(t, idxAbv < idxTa, "anomalies_by_severity before total_anomalies")
	assert.True(t, idxTa < idxTp, "total_anomalies before total_patterns")
}

func TestRenderJSON_Deterministic(t *testing.T) {
	t.Parallel()
	r := buildHubbleJSONReport()

	var buf1, buf2 strings.Builder
	err := RenderJSON(r, &buf1)
	require.NoError(t, err)
	err = RenderJSON(r, &buf2)
	require.NoError(t, err)

	assert.Equal(t, strings.TrimSpace(buf1.String()), strings.TrimSpace(buf2.String()), "RenderJSON must be deterministic")
}

func TestRenderJSON_AnomalySeveritySorted(t *testing.T) {
	t.Parallel()
	r := JSONReport{
		Summary: Summary{
			AnomaliesBySeverity: map[string]int{
				"high":   3,
				"medium": 2,
				"low":    1,
				"info":   0,
			},
		},
	}

	var buf strings.Builder
	err := RenderJSON(r, &buf)
	require.NoError(t, err)

	got := buf.String()

	// Verify severity keys are sorted alphabetically.
	idxHigh := strings.Index(got, `"high"`)
	idxInfo := strings.Index(got, `"info"`)
	idxLow := strings.Index(got, `"low"`)
	idxMedium := strings.Index(got, `"medium"`)

	assert.True(t, idxHigh < idxInfo, "high must come before info")
	assert.True(t, idxInfo < idxLow, "info must come before low")
	assert.True(t, idxLow < idxMedium, "low must come before medium")
}

// --- helper builders ---

func buildHubbleJSONReport() JSONReport {
	return JSONReport{
		Summary: Summary{
			TotalPatterns:  4,
			TotalAnomalies: 2,
			AnomaliesBySeverity: map[string]int{
				"high":   1,
				"medium": 1,
			},
		},
		Patterns: []JSONPattern{
			{Key: "default/frontend -> production/backend:8080/TCP", Src: "default/frontend", Dst: "production/backend", Port: 8080, Protocol: "TCP", Count: 150},
			{Key: "default/frontend -> default/postgres:5432/TCP", Src: "default/frontend", Dst: "default/postgres", Port: 5432, Protocol: "TCP", Count: 80},
			{Key: "kube-system/coredns -> production/backend:53/UDP", Src: "kube-system/coredns", Dst: "production/backend", Port: 53, Protocol: "UDP", Count: 200},
			{Key: "staging/api-gw -> production/backend:443/TCP", Src: "staging/api-gw", Dst: "production/backend", Port: 443, Protocol: "TCP", Count: 30},
		},
		Anomalies: []JSONAnomaly{
			{Type: "portscan", Severity: "high", Workload: "staging/api-gw", Description: "Detected scan of 25 ports from staging/api-gw within 10s"},
			{Type: "rare_flow", Severity: "medium", Workload: "default/redis", Description: "Unusual traffic pattern detected from default/redis"},
		},
	}
}

func buildCalicoJSONReport() JSONReport {
	return JSONReport{
		Summary: Summary{
			TotalPatterns:       2,
			TotalAnomalies:      0,
			AnomaliesBySeverity: map[string]int{},
		},
		Patterns: []JSONPattern{
			{Key: "default/worker -> production/api:3000/TCP", Src: "default/worker", Dst: "production/api", Port: 3000, Protocol: "TCP", Count: 50},
			{Key: "default/worker -> production/api:8080/TCP", Src: "default/worker", Dst: "production/api", Port: 8080, Protocol: "TCP", Count: 25},
		},
		Anomalies: []JSONAnomaly{},
	}
}
