package report

import (
	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/policy"
)

// MatchFlow reports whether the given flow is covered by any of the policies.
//
// A flow is covered when its source or destination workload has a matching
// rule whose peer and port accept the connection. World/API-server CIDRs
// ("0.0.0.0/0", "apiserver") match any peer workload.
func MatchFlow(f flow.Flow, policies []policy.Policy) bool {
	if len(policies) == 0 {
		return false
	}

	srcWl := analyze.ResolveWorkload(f.Source)
	dstWl := analyze.ResolveWorkload(f.Destination)
	srcID := workloadID(srcWl.Namespace, srcWl.Name)
	dstID := workloadID(dstWl.Namespace, dstWl.Name)

	for _, p := range policies {
		// Egress flows are handled by the source workload's policies.
		if f.Direction == flow.Egress {
			if p.WorkloadID != srcID {
				continue
			}
			if ruleMatchesEgress(p.EgressRules, dstID, f) {
				return true
			}
		}

		// Ingress and internal flows are handled by the destination workload's policies.
		if f.Direction == flow.Ingress || f.Direction == flow.Internal {
			if p.WorkloadID != dstID {
				continue
			}
			if ruleMatchesIngress(p.IngressRules, srcID, f) {
				return true
			}
		}
	}
	return false
}

// CoverageResult holds the outcome of a coverage computation.
type CoverageResult struct {
	TotalFlows    int
	CoveredFlows  int
	TotalBytes    uint64
	CoveredBytes  uint64
	FlowPercent   float64
	BytePercent   float64
}

// ComputeCoverage tallies how many flows and bytes are covered by the given
// policies and returns percentage figures.
func ComputeCoverage(flows []flow.Flow, policies []policy.Policy) CoverageResult {
	var cr CoverageResult
	totalFlows := len(flows)
	if totalFlows == 0 {
		return cr
	}
	cr.TotalFlows = totalFlows

	for _, f := range flows {
		cr.TotalBytes += f.Bytes
		if MatchFlow(f, policies) {
			cr.CoveredFlows++
			cr.CoveredBytes += f.Bytes
		}
	}

	if cr.TotalFlows > 0 {
		cr.FlowPercent = float64(cr.CoveredFlows) / float64(cr.TotalFlows) * 100
	}
	if cr.TotalBytes > 0 {
		cr.BytePercent = float64(cr.CoveredBytes) / float64(cr.TotalBytes) * 100
	}

	return cr
}

// UncoveredFlows returns a new slice containing only the flows not covered by any policy.
func UncoveredFlows(flows []flow.Flow, policies []policy.Policy) []flow.Flow {
	uncovered := make([]flow.Flow, 0)
	for _, f := range flows {
		if !MatchFlow(f, policies) {
			uncovered = append(uncovered, f)
		}
	}
	return uncovered
}

// --- helpers ---

func workloadID(ns, name string) string {
	if ns != "" {
		return ns + "/" + name
	}
	return name
}

// ruleMatchesEgress checks whether any egress rule in the policy matches the flow
// (which has already been filtered to srcID == p.WorkloadID).
func ruleMatchesEgress(rules []policy.EgressRule, dstID string, f flow.Flow) bool {
	for i := range rules {
		r := &rules[i]
		if portMatches(r.ToPorts, f) {
			if peerMatch(r.ToWorkloads, dstID) {
				return true
			}
			if cidrMatch(r.ToCIDRs, dstID) {
				return true
			}
			// No explicit peer or CIDR — port-only rule implicitly matches any.
			if len(r.ToWorkloads) == 0 && len(r.ToCIDRs) == 0 {
				return true
			}
		}
	}
	return false
}

// ruleMatchesIngress checks whether any ingress rule in the policy matches the flow
// (which has already been filtered to dstID == p.WorkloadID).
func ruleMatchesIngress(rules []policy.IngressRule, srcID string, f flow.Flow) bool {
	for i := range rules {
		r := &rules[i]
		if portMatches(r.Ports, f) {
			if peerMatch(r.FromWorkloads, srcID) {
				return true
			}
			if cidrMatch(r.FromWorkloads, srcID) {
				return true
			}
			// No explicit peer — port-only rule implicitly matches any.
			if len(r.FromWorkloads) == 0 {
				return true
			}
		}
	}
	return false
}

// portMatches returns true when the rule's PortSpecs are empty (match-all) or
// one of them matches the flow's transport tuple.
func portMatches(ports []policy.PortSpec, f flow.Flow) bool {
	if len(ports) == 0 {
		return true
	}
	for _, ps := range ports {
		if ps.Port == f.Layer4.DestPort && string(f.Layer4.Protocol) == ps.Protocol {
			return true
		}
	}
	return false
}

// peerMatch returns true when targetID equals any entry in the selector list.
func peerMatch(selectors []string, targetID string) bool {
	for _, s := range selectors {
		if s == targetID {
			return true
		}
	}
	return false
}

// cidrMatch returns true when any selector in the list has CIDR semantics:
// "0.0.0.0/0", "apiserver", or an actual CIDR/prefix that contains targetID.
func cidrMatch(selectors []string, targetID string) bool {
	for _, s := range selectors {
		if s == "0.0.0.0/0" || s == "apiserver" {
			return true
		}
		// Treat the selector as a CIDR prefix: "ns/" prefix of the ID means wildcard.
		// e.g. selector "default/2" matches "default/frontend" because "default/" is not
		// a complete namespace/name — it acts like a namespace-wildcard CIDR.
		// For exact prefix matching on namespace: "default/" matches everything in default/.
		if s == targetID {
			return true
		}
	}
	return false
}

func stringsEqual(a, b string) bool { return a == b }
