package tui

import (
	"cmp"
	"slices"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/simulate"
)

// allowedEntities lists the Cilium reserved entity identifiers
// that are considered valid selectable entities.
var allowedEntities = map[string]bool{
	"world":          true,
	"cluster":        true,
	"host":           true,
	"remote-node":    true,
	"kube-apiserver": true,
}

// workloadNameFromLabels tries to derive a workload name from the given labels.
// Priority: "app" > "app.kubernetes.io/name" > skip.
func workloadNameFromLabels(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	if name, ok := labels["app"]; ok {
		return name
	}
	if name, ok := labels["app.kubernetes.io/name"]; ok {
		return name
	}
	return ""
}

// isCIDR validates that a string looks like a valid IPv4/IPv6 CIDR.
// A CIDR must contain a "/" character.
func isCIDR(s string) bool {
	return strings.Contains(s, "/")
}

// ExtractSelectableObjects populates selectable workloads, entities, and CIDRs
// from a slice of loaded policies.
//
// Workloads are derived from Policy podSelector/endpointSelector labels:
//   - "app" label wins for workload name
//   - "app.kubernetes.io/name" as fallback
func ExtractSelectableObjects(policies []simulate.LoadedPolicy) SelectableObjects {
	s := SelectableObjects{
		Workloads: nil,
		Entities:  nil,
		CIDRs:     nil,
	}

	// Collect workloads: key -> (name, labels).
	type workloadKey struct {
		namespace, name string
	}
	workloadMap := make(map[workloadKey]*SelectableWorkload)

	// Collect entities: set-based dedup.
	entitySet := make(map[string]bool)

	// Collect CIDRs: set-based dedup.
	cidrSet := make(map[string]bool)

	for _, p := range policies {
		// --- Workloads ---
		var labels map[string]string
		var namespace string

		switch p.Kind {
		case "NetworkPolicy":
			if p.Network != nil {
				labels = p.Network.Spec.PodSelector.MatchLabels
				namespace = p.Network.Namespace
			}
		case "CiliumNetworkPolicy":
			if p.Cilium != nil {
				labels = p.Cilium.Spec.EndpointSelector.MatchLabels
				namespace = p.Cilium.Metadata.Namespace
			}
		}

		if labels != nil {
			name := workloadNameFromLabels(labels)
			if name != "" {
				if namespace == "" {
					namespace = "default"
				}
				key := workloadKey{namespace: namespace, name: name}
				if existing, ok := workloadMap[key]; ok {
					// Keep the richest label map (most keys).
					if len(labels) > len(existing.Labels) {
						existing.Labels = labels
					}
				} else {
					lc := make(map[string]string, len(labels))
					for k, v := range labels {
						lc[k] = v
					}
					w := &SelectableWorkload{
						Namespace: namespace,
						Name:      name,
						Labels:    lc,
					}
					workloadMap[key] = w
				}
			}
		}

		// --- Entities (CNP only) ---
		if p.Kind == "CiliumNetworkPolicy" && p.Cilium != nil {
			for _, rule := range p.Cilium.Spec.Ingress {
				for _, e := range rule.FromEntities {
					if allowedEntities[e] {
						entitySet[e] = true
					}
				}
			}
			for _, rule := range p.Cilium.Spec.Egress {
				for _, e := range rule.ToEntities {
					if allowedEntities[e] {
						entitySet[e] = true
					}
				}
			}
		}

		// --- CIDRs ---
		switch p.Kind {
		case "NetworkPolicy":
			if p.Network != nil {
				for _, egress := range p.Network.Spec.Egress {
					for _, peer := range egress.To {
						if peer.IPBlock != nil {
							if ip := peer.IPBlock.CIDR; isCIDR(ip) {
								cidrSet[ip] = true
							}
						}
					}
				}
				for _, ingress := range p.Network.Spec.Ingress {
					for _, peer := range ingress.From {
						if peer.IPBlock != nil {
							if ip := peer.IPBlock.CIDR; isCIDR(ip) {
								cidrSet[ip] = true
							}
						}
					}
				}
			}
		case "CiliumNetworkPolicy":
			if p.Cilium != nil {
				for _, rule := range p.Cilium.Spec.Ingress {
					for _, cidr := range rule.FromCIDR {
						if isCIDR(cidr) {
							cidrSet[cidr] = true
						}
					}
				}
				for _, rule := range p.Cilium.Spec.Egress {
					for _, cidr := range rule.ToCIDR {
						if isCIDR(cidr) {
							cidrSet[cidr] = true
						}
					}
				}
			}
		}
	}

	// Build sorted workload slice.
	s.Workloads = make([]SelectableWorkload, 0, len(workloadMap))
	for _, w := range workloadMap {
		s.Workloads = append(s.Workloads, *w)
	}
	slices.SortFunc(s.Workloads, func(a, b SelectableWorkload) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	// Build sorted entity list.
	s.Entities = make([]string, 0, len(entitySet))
	for e := range entitySet {
		s.Entities = append(s.Entities, e)
	}
	slices.Sort(s.Entities)

	// Build sorted CIDR list + custom item.
	s.CIDRs = make([]SelectableCIDR, 0, len(cidrSet)+1)
	for c := range cidrSet {
		s.CIDRs = append(s.CIDRs, SelectableCIDR{CIDR: c})
	}
	s.CIDRs = append(s.CIDRs, SelectableCIDR{CIDR: "Custom IP/CIDR"})
	slices.SortFunc(s.CIDRs, func(a, b SelectableCIDR) int {
		return cmp.Compare(a.CIDR, b.CIDR)
	})

	return s
}
