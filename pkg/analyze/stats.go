package analyze

import (
	"fmt"
	"sort"
	"time"

	"github.com/flowguarder/flowguarder/pkg/flow"
)

// Pattern represents an aggregated traffic pattern between two workloads.
type Pattern struct {
	// Key is a canonical "srcWorkload -> dstWorkload:port/proto" string,
	// e.g. "default/frontend-abc12 -> production/backend-xyz99:8080/TCP".
	Key string
	// SrcWorkloadID is the "namespace/name" identifier for the source workload.
	SrcWorkloadID string
	// DstWorkloadID is the "namespace/name" identifier for the destination workload.
	DstWorkloadID string
	// Port is the destination Layer 4 port.
	Port uint16
	// Protocol is the Layer 4 protocol (e.g. "TCP", "UDP").
	Protocol string
	// Count is the number of observed flows matching this pattern.
	Count uint64
	// Bytes is the total bytes observed for this pattern (0 if unavailable).
	Bytes uint64
	// FirstSeen is the earliest timestamp observed for this pattern.
	FirstSeen time.Time
	// LastSeen is the latest timestamp observed for this pattern.
	LastSeen time.Time
	// Direction is the traffic direction of the aggregated flows.
	Direction flow.Direction
}

// patternKey builds a canonical "srcWL -> dstWL:port/proto" key string.
func patternKey(srcWL, dstWL, port, proto string) string {
	return fmt.Sprintf("%s -> %s:%s/%s", srcWL, dstWL, port, proto)
}

// SortByCount sorts patterns in-place descending by Count, using Key as a
// deterministic tiebreaker so sorted output is always reproducible.
func SortByCount(p []Pattern) []Pattern {
	if p == nil {
		return make([]Pattern, 0)
	}
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].Count != p[j].Count {
			return p[i].Count > p[j].Count
		}
		return p[i].Key < p[j].Key
	})
	return p
}

// FilterDirection returns only the patterns matching the given direction.
func FilterDirection(ps []Pattern, d flow.Direction) []Pattern {
	result := make([]Pattern, 0, len(ps))
	for _, p := range ps {
		if p.Direction == d {
			result = append(result, p)
		}
	}
	return result
}

// patternAgg holds running aggregates for a single pattern key.
type patternAgg struct {
	srcID, dstID string
	port         uint16
	protocol     string
	dir          flow.Direction
	firstSeen    time.Time
	lastSeen     time.Time
	count        uint64
	bytes        uint64
}

// ComputePatterns aggregates flows into workload-level traffic patterns.
//
// For each flow, ResolveWorkload is called on Source and Destination endpoints
// to resolve workload names, a canonical pattern key is assembled, and flows
// are grouped and aggregated (count, bytes, first/last seen).
//
// Results are sorted deterministically by pattern key.  When flows is empty or
// nil an empty (non-nil) slice is returned.
func ComputePatterns(flows []flow.Flow, workloads Workloads) []Pattern {
	_ = workloads // accepted for pipeline consistency; resolution is per-flow

	if len(flows) == 0 {
		return make([]Pattern, 0)
	}

	agg := make(map[string]*patternAgg, len(flows))

	for _, f := range flows {
		srcWL := ResolveWorkload(f.Source)
		dstWL := ResolveWorkload(f.Destination)

		srcID := WorkloadID(srcWL.Namespace + "/" + srcWL.Name)
		dstID := WorkloadID(dstWL.Namespace + "/" + dstWL.Name)

		proto := string(f.Layer4.Protocol)
		if proto == "" {
			proto = "UNKNOWN"
		}

		pk := patternKey(string(srcID), string(dstID), fmt.Sprintf("%d", f.Layer4.DestPort), proto)

		a, exists := agg[pk]
		if !exists {
			a = &patternAgg{
				srcID:     string(srcID),
				dstID:     string(dstID),
				port:      f.Layer4.DestPort,
				protocol:  proto,
				dir:       f.Direction,
				firstSeen: f.Time,
				lastSeen:  f.Time,
			}
			agg[pk] = a
		}

		a.count++
		a.bytes += f.Bytes

		if f.Time.Before(a.firstSeen) {
			a.firstSeen = f.Time
		}
		if f.Time.After(a.lastSeen) {
			a.lastSeen = f.Time
		}
	}

	result := make([]Pattern, 0, len(agg))
	for _, a := range agg {
		result = append(result, Pattern{
			Key:           patternKey(a.srcID, a.dstID, fmt.Sprintf("%d", a.port), a.protocol),
			SrcWorkloadID: a.srcID,
			DstWorkloadID: a.dstID,
			Port:          a.port,
			Protocol:      a.protocol,
			Count:         a.count,
			Bytes:         a.bytes,
			FirstSeen:     a.firstSeen,
			LastSeen:      a.lastSeen,
			Direction:     a.dir,
		})
	}

	// Deterministic output: sort by key.
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Key < result[j].Key
	})

	return result
}
