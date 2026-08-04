package report

import (
	"fmt"
	"sort"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/flow"
)

// FlowAggregate represents an aggregated flow entry summarizing traffic
// between two endpoints grouped by (source, destination, port, protocol).
type FlowAggregate struct {
	Src    string
	Dst    string
	Port   uint16
	Proto  string
	Bytes  uint64
	Count  int
	Policy string
}

// aggregateKey forms a deterministic aggregation key for grouping flows.
func aggregateKey(src, dst string, port uint16, proto string) string {
	return fmt.Sprintf("%s|%s|%d|%s", src, dst, port, proto)
}

// TopFlows aggregates flows by (source, destination, port, protocol) and
// returns the top-N aggregates sorted by total bytes descending.
//
// Deterministic ordering: primary sort by bytes desc, secondary tiebreak
// by (Src, Dst, Port, Proto). When n <= 0, all aggregates are returned.
func TopFlows(flows []flow.Flow, workloads analyze.Workloads, n int) []FlowAggregate {
	_ = workloads // reserved for future IP-to-workload lookups
	type bucket struct {
		key string
		s   FlowAggregate
	}

	m := make(map[string]*bucket)
	for _, f := range flows {
		sWork := analyze.ResolveWorkload(f.Source)
		dWork := analyze.ResolveWorkload(f.Destination)
		src := fmt.Sprintf("%s/%s", sWork.Namespace, sWork.Name)
		dst := fmt.Sprintf("%s/%s", dWork.Namespace, dWork.Name)
		k := aggregateKey(src, dst, f.Layer4.DestPort, string(f.Layer4.Protocol))
		b, ok := m[k]
		if !ok {
			b = &bucket{key: k, s: FlowAggregate{
				Src:   src,
				Dst:   dst,
				Port:  f.Layer4.DestPort,
				Proto: string(f.Layer4.Protocol),
			}}
			m[k] = b
		}
		b.s.Bytes += f.Bytes
		b.s.Count++
	}

	results := make([]FlowAggregate, 0, len(m))
	for _, b := range m {
		results = append(results, b.s)
	}

	sliceSortByBytesDesc(results)
	if n > 0 && n < len(results) {
		results = results[:n]
	}
	return results
}

// EgressWorldFlows filters flows to those with PeerType == EgressWorld,
// aggregates by (source, destination, port, protocol), and returns the
// top-N aggregates sorted by total bytes descending.
//
// When n <= 0, all egress-world aggregates are returned.
func EgressWorldFlows(flows []flow.Flow, workloads analyze.Workloads, n int) []FlowAggregate {
	_ = workloads
	type bucket struct {
		key string
		s   FlowAggregate
	}

	m := make(map[string]*bucket)
	for _, f := range flows {
		if f.PeerType != flow.EgressWorld {
			continue
		}
		sWork := analyze.ResolveWorkload(f.Source)
		dWork := analyze.ResolveWorkload(f.Destination)
		src := fmt.Sprintf("%s/%s", sWork.Namespace, sWork.Name)
		dst := fmt.Sprintf("%s/%s", dWork.Namespace, dWork.Name)
		k := aggregateKey(src, dst, f.Layer4.DestPort, string(f.Layer4.Protocol))
		b, ok := m[k]
		if !ok {
			b = &bucket{key: k, s: FlowAggregate{
				Src:   src,
				Dst:   dst,
				Port:  f.Layer4.DestPort,
				Proto: string(f.Layer4.Protocol),
			}}
			m[k] = b
		}
		b.s.Bytes += f.Bytes
		b.s.Count++
	}

	results := make([]FlowAggregate, 0, len(m))
	for _, b := range m {
		results = append(results, b.s)
	}

	sliceSortByBytesDesc(results)
	if n > 0 && n < len(results) {
		results = results[:n]
	}
	return results
}

// DroppedFlows filters flows to those with Verdict != allowed,
// aggregates by (source, destination, port, protocol), and returns all
// aggregated drop entries sorted by total bytes descending.
//
// The Policy field is set from f.PolicyName if non-empty, otherwise from
// f.DropReason.
// The n parameter is ignored (all drops are always returned).
func DroppedFlows(flows []flow.Flow, workloads analyze.Workloads, n int) []FlowAggregate {
	_ = workloads
	_ = n

	type bucket struct {
		key string
		s   FlowAggregate
	}

	m := make(map[string]*bucket)
	for _, f := range flows {
		if f.Verdict.IsAllowed() {
			continue
		}
		sWork := analyze.ResolveWorkload(f.Source)
		dWork := analyze.ResolveWorkload(f.Destination)
		src := fmt.Sprintf("%s/%s", sWork.Namespace, sWork.Name)
		dst := fmt.Sprintf("%s/%s", dWork.Namespace, dWork.Name)
		k := aggregateKey(src, dst, f.Layer4.DestPort, string(f.Layer4.Protocol))
		b, ok := m[k]
		if !ok {
			b = &bucket{key: k, s: FlowAggregate{
				Src:   src,
				Dst:   dst,
				Port:  f.Layer4.DestPort,
				Proto: string(f.Layer4.Protocol),
			}}
			m[k] = b
		}
		b.s.Bytes += f.Bytes
		b.s.Count++

		// Policy: prefer PolicyName, fall back to DropReason.
		// Set only once on first flow that fills this bucket.
		if b.s.Policy == "" {
			policy := f.PolicyName
			if policy == "" {
				policy = f.DropReason
			}
			b.s.Policy = policy
		}
	}

	results := make([]FlowAggregate, 0, len(m))
	for _, b := range m {
		results = append(results, b.s)
	}

	sliceSortByBytesDesc(results)
	return results
}

// sliceSortByBytesDesc sorts aggregates by bytes descending, with
// deterministic tie-breaking by (Src, Dst, Port, Proto).
func sliceSortByBytesDesc(s []FlowAggregate) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Bytes != s[j].Bytes {
			return s[i].Bytes > s[j].Bytes
		}
		// Tiebreak: (Src, Dst, Port, Proto) ascending.
		if s[i].Src != s[j].Src {
			return s[i].Src < s[j].Src
		}
		if s[i].Dst != s[j].Dst {
			return s[i].Dst < s[j].Dst
		}
		if s[i].Port != s[j].Port {
			return s[i].Port < s[j].Port
		}
		return s[i].Proto < s[j].Proto
	})
}
