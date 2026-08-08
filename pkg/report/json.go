package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// JSONReport holds data rendered by RenderJSON.
type JSONReport struct {
	Summary
	Patterns  []JSONPattern
	Anomalies []JSONAnomaly
}

// JSONPattern represents one aggregated traffic pattern for the JSON report.
type JSONPattern struct {
	Key      string `json:"key"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Count    uint64 `json:"count"`
}

// JSONAnomaly represents one detected anomaly for the JSON report.
type JSONAnomaly struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Workload    string `json:"workload"`
	Description string `json:"description"`
}

// RenderJSON writes deterministic JSON with sorted keys to w.
func RenderJSON(r JSONReport, w io.Writer) error {
	b := &orderedMap{keys: []string(nil), items: make(map[string]interface{})}

	// Build summary object.
	sum := make(map[string]interface{}, 3)
	sum["total_patterns"] = r.TotalPatterns
	sum["total_anomalies"] = r.TotalAnomalies
	sum["anomalies_by_severity"] = r.sortedAnomalySeverity()

	b.items["summary"] = sum

	// Patterns list.
	pats := make([]map[string]interface{}, len(r.Patterns))
	for i, p := range r.Patterns {
		pats[i] = map[string]interface{}{
			"key":      p.Key,
			"src":      p.Src,
			"dst":      p.Dst,
			"port":     p.Port,
			"protocol": p.Protocol,
			"count":    p.Count,
		}
	}
	b.items["patterns"] = pats

	// Anomalies list.
	anoms := make([]map[string]interface{}, len(r.Anomalies))
	for i, a := range r.Anomalies {
		anoms[i] = map[string]interface{}{
			"type":        a.Type,
			"severity":    a.Severity,
			"workload":    a.Workload,
			"description": a.Description,
		}
	}
	b.items["anomalies"] = anoms

	data, err := json.Marshal(b.sorted())
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if _, err := fmt.Fprint(w, indentedJSON(data)+"\n"); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

// orderedMap is a minimal helper to ensure top-level keys are in a fixed order.
// We don't actually need a full map — we build objects directly.
type orderedMap struct {
	keys  []string
	items map[string]interface{}
}

// sorted returns a map whose keys appear in insertion order (by iterating keys in order).
// json.Marshal doesn't guarantee order, so we use a custom approach: serialize each field.
func (o *orderedMap) sorted() map[string]interface{} {
	// Actually, Go's encoding/json doesn't preserve map key order.
	// The reliable way is to build top-level sorted keys object manually.
	return o.items
}

func (r JSONReport) sortedAnomalySeverity() map[string]int {
	if len(r.AnomaliesBySeverity) == 0 {
		return make(map[string]int)
	}
	bs := make(map[string]int, len(r.AnomaliesBySeverity))
	for k, v := range r.AnomaliesBySeverity {
		bs[k] = v
	}
	return bs
}

// indentedJSON takes compact JSON bytes and re-indents them with sort-keys.
func indentedJSON(data []byte) string {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	// We'll use map[string]interface{} to force key sorting during marshaling.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return string(data)
	}
	sorted := sortMapKeys(m)
	out, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(out)
}

// sortMapKeys recursively sorts map keys and returns a map[string]interface{}.
func sortMapKeys(m map[string]interface{}) map[string]interface{} {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sorted := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		v := m[k]
		if innerMap, ok := v.(map[string]interface{}); ok {
			sorted[k] = sortMapKeys(innerMap)
		} else if slice, ok := v.([]interface{}); ok {
			sSorted := make([]interface{}, len(slice))
			for i, item := range slice {
				if innerMap, ok := item.(map[string]interface{}); ok {
					sSorted[i] = sortMapKeys(innerMap)
				} else {
					sSorted[i] = item
				}
			}
			sorted[k] = sSorted
		} else {
			sorted[k] = v
		}
	}
	return sorted
}
