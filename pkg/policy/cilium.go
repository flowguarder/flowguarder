// Package policy generates Kubernetes NetworkPolicy and CiliumNetworkPolicy
// manifests from observed network flow patterns.
package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"gopkg.in/yaml.v3"
)

// --- CiliumNetworkPolicy CRD model ---

// CiliumNetworkPolicy is the CiliumNetworkPolicy (cilium.io/v2) CRD struct.
// It mirrors the Cilium CNP schema with Metadata, Spec (endpointSelector,
// ingress, egress rules, and endpoint Defaults).
type CiliumNetworkPolicy struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   CNPMetadata `yaml:"metadata"`
	Spec       CNPSpec     `yaml:"spec"`
}

// CNPHeadComment is an optional comment prepended to each CNP document.
var CNPHeadComment = "Flowguarder-generated CiliumNetworkPolicy — do not edit manually."

// worldEntities holds the Cilium entity identifiers that together cover all
// observable traffic sources: external world, in-cluster peers, local hosts,
// and remote cluster nodes (REVIEW7 BUG 6).
var worldEntities = []string{"world", "cluster", "host", "remote-node"}

// isWorldPeer checks whether a peer string represents a "world" (match-all)
// destination.  These values are rendered as Cilium entities instead of the
// catch-all CIDR 0.0.0.0/0 (REVIEW7 BUG 6).
// "entity:world" is treated the same — it maps to worldEntities.
func isWorldPeer(peer string) bool {
	switch peer {
	case "0.0.0.0/0", "world", "pub", "pvt", "-", "", "entity:world":
		return true
	}
	return false
}

// CNPMetadata holds standard Kubernetes metadata for a CNP.
type CNPMetadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// CNPSpec holds the Cilium security policy specification.
type CNPSpec struct {
	EndpointSelector CNPEntitySelector `yaml:"endpointSelector,omitempty"`
	Ingress          []CNPIngressRule  `yaml:"ingress,omitempty"`
	Egress           []CNPEgressRule   `yaml:"egress,omitempty"`
	EndpointDefaults map[string]bool   `yaml:"endpointDefaults,omitempty"`
}

// CNPEntitySelector selects Cilium endpoints by Kubernetes labels.
type CNPEntitySelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// CNPIngressRule represents a single ingress security rule.
type CNPIngressRule struct {
	FromEndpoints []CNPEntitySelector `yaml:"fromEndpoints,omitempty"`
	FromCIDR      []string            `yaml:"fromCIDR,omitempty"`
	FromEntities  []string            `yaml:"fromEntities,omitempty"`
	ToPorts       []CNPToPorts        `yaml:"toPorts,omitempty"`
}

// CNPEgressRule represents a single egress security rule.
type CNPEgressRule struct {
	ToEndpoints []CNPEntitySelector `yaml:"toEndpoints,omitempty"`
	ToCIDR      []string            `yaml:"toCIDR,omitempty"`
	ToEntities  []string            `yaml:"toEntities,omitempty"`
	ToFQDNs     []FQDNSelector      `yaml:"toFQDNs,omitempty"`
	ToServices  []ServiceSelector   `yaml:"toServices,omitempty"`
	ToPorts     []CNPToPorts        `yaml:"toPorts,omitempty"`
}

// CNPToPorts represents a single toPorts entry containing L4 ports and optional L7 rules.
type CNPToPorts struct {
	Ports []PortRule `yaml:"ports,omitempty"`
	Rules *CNPRules  `yaml:"rules,omitempty"`
}

// CNPRules holds L7 (application-layer) rules nested inside a toPorts entry.
type CNPRules struct {
	DNS []CNPDNSRule `yaml:"dns,omitempty"`
}

// CNPDNSRule represents a single DNS rule with match constraints.
type CNPDNSRule struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

// FQDNSelector selects traffic to fully-qualified domain names.
type FQDNSelector struct {
	MatchName    string `yaml:"matchName,omitempty"`
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

// ServiceSelector selects traffic to Kubernetes Services.
type ServiceSelector struct {
	Namespace string `yaml:"namespace,omitempty"`
	Name      string `yaml:"name"`
}

// PortRule describes a single L4 port/protocol pair for a Cilium rule.
type PortRule struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

// --- Builder ---

// BuildCilium converts a list of standard Policy objects and a slice of flows
// into CiliumNetworkPolicy objects suitable for applying with `kubectl apply`.
//
// For each workload it creates one CNP with:
//   - An endpointSelector derived from the workload's pod labels.
//   - Ingress rules from policy ingress data.
//   - Egress rules from policy egress data.
//   - L7 DNS rules when port 53/ANY is observed.
//   - ToFQDNs rules when flows contain L7 DNS query names or TLS SNI names.
//
// Reserved peers (apiserver, entity:*) are rendered as Cilium entities
// (fromEntities/toEntities) instead of CIDRs, fixing REVIEW8 BUG 10.
//
// Output is deterministic: sorted by CNP metadata.name.
func BuildCilium(policies []Policy, flows []flow.Flow, workloads analyze.Workloads) []CiliumNetworkPolicy {
	cnps := make([]CiliumNetworkPolicy, 0, len(policies))

	// Collect L7 hints by workload from flows.
	l7Hints := collectL7Hints(flows)

	for i := range policies {
		p := &policies[i]
		cnp := buildCNPFromPolicy(p, l7Hints, workloads)
		if cnp != nil {
			cnps = append(cnps, *cnp)
		}
	}

	sort.Slice(cnps, func(i, j int) bool {
		return cnps[i].Metadata.Name < cnps[j].Metadata.Name
	})

	return cnps
}

// collectL7Hints aggregates L7 hints per workload from flows.
func collectL7Hints(flows []flow.Flow) map[string][]L7HintData {
	hints := make(map[string][]L7HintData)
	for _, f := range flows {
		if f.L7 == nil {
			continue
		}
		key := wKey(f.Source.Namespace, f.Source.PodName)
		val := wKey(f.Destination.Namespace, f.Destination.PodName)
		switch f.Direction {
		case flow.Egress:
			hints[key] = append(hints[key], L7HintData{
				Query: f.L7.Query,
				Host:  f.L7.Host,
				Type:  f.L7.Type,
			})
			hints[val] = append(hints[val], L7HintData{
				Query: f.L7.Query,
				Host:  f.L7.Host,
				Type:  f.L7.Type,
			})
		case flow.Ingress, flow.Internal:
			hints[val] = append(hints[val], L7HintData{
				Query: f.L7.Query,
				Host:  f.L7.Host,
				Type:  f.L7.Type,
			})
			hints[key] = append(hints[key], L7HintData{
				Query: f.L7.Query,
				Host:  f.L7.Host,
				Type:  f.L7.Type,
			})
		}
	}
	return hints
}

// L7HintData holds extracted L7 context from a flow.
type L7HintData struct {
	Query string
	Host  string
	Type  string
}

// normalizeProtocol returns "ANY" for empty or already-ANY input;
// otherwise returns the input protocol unchanged.
func normalizeProtocol(proto string) string {
	if proto == "" || proto == "ANY" {
		return "ANY"
	}
	return proto
}

// appendDNSRule appends rule to entry.Rules.DNS only if no identical rule
// (same MatchPattern + MatchName) is already present, preventing duplicate
// wildcard DNS entries in the same toPorts block.
func appendDNSRule(entry *CNPToPorts, rule CNPDNSRule) {
	if entry.Rules == nil {
		entry.Rules = &CNPRules{}
	}
	for _, existing := range entry.Rules.DNS {
		if existing.MatchPattern == rule.MatchPattern && existing.MatchName == rule.MatchName {
			return
		}
	}
	entry.Rules.DNS = append(entry.Rules.DNS, rule)
}

// buildCNPFromPolicy converts a single Policy into a CiliumNetworkPolicy.
func buildCNPFromPolicy(p *Policy, l7Hints map[string][]L7HintData, workloads analyze.Workloads) *CiliumNetworkPolicy {
	// Build endpoint selector from workload's stable labels,
	// falling back to {"app": WorkloadName} for unknown/label-less workloads.
	endpointLabels := map[string]string{
		"app": p.WorkloadName,
	}
	if wd, ok := workloads[analyze.WorkloadID(p.WorkloadID)]; ok {
		stable := analyze.StripUnstableLabels(analyze.ResolveSelectors(wd))
		if len(stable) > 0 {
			endpointLabels = stable
		}
	}

	cnp := &CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: CNPMetadata{
			Name:      sanitizeName(p.WorkloadName),
			Namespace: p.WorkloadNamespace,
			Labels: map[string]string{
				"app":                p.WorkloadName,
				"policy.k8s.io/name": "flowguarder",
			},
			Annotations: map[string]string{
				"flowguarder.io/workload": p.WorkloadID,
			},
		},
		Spec: CNPSpec{
			EndpointSelector: CNPEntitySelector{
				MatchLabels: endpointLabels,
			},
		},
	}

	// Ingress rules.
	for _, ir := range p.IngressRules {
		rule := CNPIngressRule{}

		// FromEndpoints / FromEntities / FromCIDR from workload selectors.
		if len(ir.FromEntities) > 0 {
			// Entity sentinel path: expand via resolveEntitySet and SKIP FromWorkloads entirely.
			for _, ent := range ir.FromEntities {
				rule.FromEntities = append(rule.FromEntities, resolveEntitySet(ent)...)
			}
			rule.FromEntities = dedupSorted(rule.FromEntities)
		} else {
			for _, wl := range ir.FromWorkloads {
				// 1. isWorldPeer first (catches "world" AND "entity:world") → worldEntities.
				if isWorldPeer(wl) {
					rule.FromEntities = append(rule.FromEntities, worldEntities...)
					continue
				}
				// 2. "entity:" prefix → split on `,`, dedup, sort → FromEntities.
				if strings.HasPrefix(wl, "entity:") {
					labels := strings.Split(wl[len("entity:"):], ",")
					// dedup + sort
					normalized := dedupSorted(labels)
					rule.FromEntities = append(rule.FromEntities, normalized...)
					continue
				}
				// 3. "apiserver" → explicit entity list.
				if wl == "apiserver" {
					rule.FromEntities = append(rule.FromEntities, "kube-apiserver", "host", "remote-node")
					continue
				}
				// 4. CIDR guard → FromCIDR.
				if _, _, err := net.ParseCIDR(wl); err == nil {
					rule.FromCIDR = append(rule.FromCIDR, wl)
					continue
				}
				// 5. workload selector → FromEndpoints.
				if sel := parseWorkloadSelector(wl, p.WorkloadNamespace, workloads); sel != nil {
					rule.FromEndpoints = append(rule.FromEndpoints, *sel)
				}
			}
		}

		// ToPorts.
		for _, ps := range ir.Ports {
			proto := normalizeProtocol(string(ps.Protocol))
			entry := CNPToPorts{
				Ports: []PortRule{{Port: itoa(int(ps.Port)), Protocol: proto}},
			}
			rule.ToPorts = append(rule.ToPorts, entry)
		}

		cnp.Spec.Ingress = append(cnp.Spec.Ingress, rule)
	}

	// Egress rules.
	for _, er := range p.EgressRules {
		rule := CNPEgressRule{}

		// ToEndpoints / ToEntities / ToCIDR.
		if len(er.ToEntities) > 0 {
			// Entity sentinel path: expand via resolveEntitySet and SKIP ToWorkloads + ToCIDRs entirely.
			for _, ent := range er.ToEntities {
				rule.ToEntities = append(rule.ToEntities, resolveEntitySet(ent)...)
			}
			rule.ToEntities = dedupSorted(rule.ToEntities)
		} else {
			// ToEndpoints / ToCIDR from ToWorkloads.
			for _, wl := range er.ToWorkloads {
				// 1. CIDR guard → ToCIDR (must come before parseWorkloadSelector).
				if _, _, err := net.ParseCIDR(wl); err == nil {
					rule.ToCIDR = append(rule.ToCIDR, wl)
					continue
				}
				// 2. workload selector → ToEndpoints.
				if sel := parseWorkloadSelector(wl, p.WorkloadNamespace, workloads); sel != nil {
					rule.ToEndpoints = append(rule.ToEndpoints, *sel)
				}
			}

			// ToNamespaces: append a ToEndpoints peer per namespace.
			for _, ns := range er.ToNamespaces {
				if ns != "" {
					rule.ToEndpoints = append(rule.ToEndpoints, CNPEntitySelector{
						MatchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": ns},
					})
				}
			}

			// ToEntities / ToCIDR from ToCIDRs.
			for _, cidr := range er.ToCIDRs {
				// 1. isWorldPeer first (catches "world" AND "entity:world") → worldEntities.
				if isWorldPeer(cidr) {
					rule.ToEntities = append(rule.ToEntities, worldEntities...)
					continue
				}
				// 2. "entity:" prefix → split on `,`, dedup, sort → ToEntities.
				if strings.HasPrefix(cidr, "entity:") {
					labels := strings.Split(cidr[len("entity:"):], ",")
					normalized := dedupSorted(labels)
					rule.ToEntities = append(rule.ToEntities, normalized...)
					continue
				}
				// 3. "apiserver" → explicit entity list (kube-apiserver, host, remote-node).
				if cidr == "apiserver" {
					rule.ToEntities = append(rule.ToEntities, "kube-apiserver", "host", "remote-node")
					continue
				}
				// 4. Fallback: emit as ToCIDR.
				rule.ToCIDR = append(rule.ToCIDR, cidr)
			}
		}

		// ToFQDNs from L7 hints.
		var fqdns []string
		fqdnSet := make(map[string]bool)
		for _, hint := range findEgressHints(p, l7Hints) {
			// DNS query names and TLS SNI become FQDN targets.
			if hint.Type == "dns" && hint.Query != "" && !fqdnSet[hint.Query] {
				fqdnSet[hint.Query] = true
				fqdns = append(fqdns, hint.Query)
			}
			if hint.Type == "tls" && hint.Host != "" && !fqdnSet[hint.Host] {
				fqdnSet[hint.Host] = true
				fqdns = append(fqdns, hint.Host)
			}
		}

		for _, fq := range dedupStrings(fqdns) {
			rule.ToFQDNs = append(rule.ToFQDNs, FQDNSelector{
				MatchPattern: fq + "*", // match subdomains too
			})
		}

		// ToPorts for workload egress.
		for _, ps := range er.ToPorts {
			proto := normalizeProtocol(string(ps.Protocol))
			entry := CNPToPorts{
				Ports: []PortRule{{Port: itoa(int(ps.Port)), Protocol: proto}},
			}
			if ps.Port == 53 {
				appendDNSRule(&entry, CNPDNSRule{MatchPattern: "*"})
			}
			rule.ToPorts = append(rule.ToPorts, entry)
		}

		cnp.Spec.Egress = append(cnp.Spec.Egress, rule)
	}

	// Remove empty slices for clean output.
	if len(cnp.Spec.Ingress) == 0 {
		cnp.Spec.Ingress = nil
	}
	if len(cnp.Spec.Egress) == 0 {
		cnp.Spec.Egress = nil
	}

	return cnp
}

// findEgressHints returns L7 hints for egress FQDN generation.
func findEgressHints(p *Policy, allHints map[string][]L7HintData) []L7HintData {
	return allHints[p.WorkloadID]
}

// parseWorkloadSelector parses a workload identifier into a CNP entity selector.
// Supported formats:
//   - Comma-separated segments (srcSelectorFor format from builder.go):
//     "ns/name,label1=v1,label2=v2"
//   - "key=value"      → MatchLabels={key:value}
//   - "namespace/name" → resolves to workload's stable labels (via workloads map),
//     falls back to {"app": name} when unknown or label-less.
//   - "name"           → MatchLabels={"app": name}
//
// When peerNs (from the workload or segment) differs from policyNs,
// the explicit key "k8s:io.kubernetes.pod.namespace" is injected so
// that Cilium namespaced CNP fromEndpoints/toEndpoints match endpoints
// across namespaces (REVIEW7 BUG 5).
func parseWorkloadSelector(sel, policyNs string, workloads analyze.Workloads) *CNPEntitySelector {
	labels := make(map[string]string)
	for _, seg := range strings.Split(sel, ",") {
		trimmed := strings.TrimSpace(seg)
		if trimmed == "" {
			continue
		}
		// key=value label segment (explicit segments win over workload labels).
		if eq := strings.IndexByte(trimmed, '='); eq > 0 {
			key, value := trimmed[:eq], trimmed[eq+1:]
			if key != "" {
				labels[key] = value
			}
			continue
		}
		// namespace/name segment – resolve stable labels from workloads when known.
		if slash := strings.IndexByte(trimmed, '/'); slash > 0 {
			ns, name := trimmed[:slash], trimmed[slash+1:]
			if ns != "" && name != "" {
				var peerNs string
				var foundWorkload bool
				if workloads != nil {
					if wd, ok := workloads[analyze.WorkloadID(ns+"/"+name)]; ok {
						stable := analyze.StripUnstableLabels(analyze.ResolveSelectors(wd))
						for k, v := range stable {
							if _, exists := labels[k]; !exists {
								labels[k] = v
							}
						}
						if len(stable) > 0 {
							peerNs = wd.Namespace
							foundWorkload = true
						}
					}
				}
				// Cross-namespace label injection (REVIEW7 BUG 5):
				// inject explicit namespace key whenever peer differs from policy ns.
				if _, exists := labels["k8s:io.kubernetes.pod.namespace"]; !exists {
					if peerNs != "" && peerNs != policyNs {
						labels["k8s:io.kubernetes.pod.namespace"] = peerNs
					}
				}
				// zero stable labels / unknown → fall through to set app:name
				// and re-resolve peerNs from segment.
				if !foundWorkload {
					if peerNs == "" {
						peerNs = ns
					}
					if _, exists := labels["app"]; !exists {
						labels["app"] = name
					}
					// Re-inject namespace key for unknown-workload path (peerNs derived from segment).
					if _, exists := labels["k8s:io.kubernetes.pod.namespace"]; !exists {
						if peerNs != "" && peerNs != policyNs {
							labels["k8s:io.kubernetes.pod.namespace"] = peerNs
						}
					}
				}
				continue
			}
		}
		// Bare name.
		if _, exists := labels["app"]; !exists {
			labels["app"] = trimmed
		}
	}
	if len(labels) == 0 {
		return &CNPEntitySelector{MatchLabels: map[string]string{"app": sel}}
	}
	return &CNPEntitySelector{MatchLabels: labels}
}

// dedupStrings returns a deduplicated, sorted copy of a string slice.
func dedupStrings(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range s {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// dedupSorted returns a deduplicated, sorted copy of a string slice.
// Used for entity: label lists from the sentinel contract.
func dedupSorted(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range s {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

// resolveEntitySet expands an "entity:<list>" sentinel into the Cilium entity
// names to emit as fromEntities/toEntities, applying the node-family closure:
// reserved host/remote-node peers always render as BOTH host AND remote-node
// (REVIEW8 §3); "world" expands to worldEntities (world, cluster, host,
// remote-node). Deterministic: sorted + deduped.
func resolveEntitySet(ent string) []string {
	if !strings.HasPrefix(ent, "entity:") {
		return nil
	}
	labels := strings.Split(ent[len("entity:"):], ",")
	normalized := dedupSorted(labels)

	var out []string
	hasWorld := false
	hasHost := false
	hasRemoteNode := false

	for _, l := range normalized {
		switch l {
		case "world":
			hasWorld = true
		case "host":
			hasHost = true
		case "remote-node":
			hasRemoteNode = true
		default:
			out = append(out, l)
		}
	}

	if hasWorld {
		out = append(out, worldEntities...)
	}
	if hasHost || hasRemoteNode {
		out = append(out, "host", "remote-node")
	}

	return dedupSorted(out)
}

// WriteCiliumYAML writes a list of CiliumNetworkPolicy objects to a directory
// as separate YAML files named "policy-<name>.yaml", one per workload.
// Each file includes the head comment and YAML anchors for determinism.
func WriteCiliumYAML(cnps []CiliumNetworkPolicy, dir string) error {
	if len(cnps) == 0 {
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("write cilium yaml: %w", err)
	}

	for _, cnp := range cnps {
		data, err := marshalCNPWithComment(cnp, CNPHeadComment)
		if err != nil {
			return fmt.Errorf("marshal cnp %q: %w", cnp.Metadata.Name, err)
		}

		fname := sanitizeName(cnp.Metadata.Namespace) + "-" + sanitizeName(cnp.Metadata.Name) + ".yaml"
		fpath := filepath.Join(dir, fname)
		if err := os.WriteFile(fpath, data, 0644); err != nil {
			return fmt.Errorf("write cnp file %q: %w", fname, err)
		}
	}

	return nil
}

// marshalCNPWithComment marshals a CNP with an optional YAML comment header.
func marshalCNPWithComment(cnp CiliumNetworkPolicy, comment string) ([]byte, error) {
	// Marshal to YAML.
	data, err := yaml.Marshal(&cnp)
	if err != nil {
		return nil, fmt.Errorf("yaml marshal: %w", err)
	}

	// Prepend comment as YAML comment on first line if set.
	if comment != "" {
		// Wrap comment lines with # and ensure a blank line after.
		lines := splitLines(comment)
		var header string
		for i, line := range lines {
			header += "# " + line + "\n"
			if i == len(lines)-1 {
				header += "\n---\n" // document separator
			}
		}
		return append([]byte(header), data...), nil
	}

	return data, nil
}

// splitLines splits a string by newline.
func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// sanitizeName produces a Kubernetes-safe name from input.
// Replaces non-alphanumeric chars (except '-' and '.') with '-'.
// Ensures the name starts with a letter.
func sanitizeName(s string) string {
	var out []byte
	for i, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' {
			out = append(out, byte(ch))
		} else {
			if i > 0 {
				out = append(out, '-')
			}
		}
	}
	result := string(out)
	if result == "" {
		return "unknown"
	}
	if result[0] < 'a' || result[0] > 'z' {
		result = "a" + result
	}
	return result
}
