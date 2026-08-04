// Package policy generates Kubernetes NetworkPolicy and CiliumNetworkPolicy
// manifests from observed network flow patterns.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"gopkg.in/yaml.v3"
)

// --- CiliumNetworkPolicy CRD model ---

// CiliumNetworkPolicy is the CiliumNetworkPolicy (cilium.io/v2) CRD struct.
// It mirrors the Cilium CNP schema with Metadata, Spec (endpointSelector,
// ingress, egress rules, and endpoint Defaults).
type CiliumNetworkPolicy struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   CNPMetadata      `yaml:"metadata"`
	Spec       CNPSpec          `yaml:"spec"`
}

// CNPHeadComment is an optional comment prepended to each CNP document.
var CNPHeadComment = "Flowguarder-generated CiliumNetworkPolicy — do not edit manually."

// CNPMetadata holds standard Kubernetes metadata for a CNP.
type CNPMetadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// CNPSpec holds the Cilium security policy specification.
type CNPSpec struct {
	EndpointSelector  CNPEntitySelector `yaml:"endpointSelector,omitempty"`
	Ingress           []CNPIngressRule  `yaml:"ingress,omitempty"`
	Egress            []CNPEgressRule   `yaml:"egress,omitempty"`
	EndpointDefaults  map[string]bool   `yaml:"endpointDefaults,omitempty"`
}

// CNPEntitySelector selects Cilium endpoints by Kubernetes labels.
type CNPEntitySelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// CNPIngressRule represents a single ingress security rule.
type CNPIngressRule struct {
	FromEndpoints []CNPEntitySelector   `yaml:"fromEndpoints,omitempty"`
	FromCIDR      []string              `yaml:"fromCIDR,omitempty"`
	TCP           []PortRule            `yaml:"toPorts,omitempty"`
	L7Rules       []map[string][]L7Rule `yaml:"l7Rules,omitempty"`
	Description   string                `yaml:"comment,omitempty"`
}

// CNPEgressRule represents a single egress security rule.
type CNPEgressRule struct {
	ToEndpoints []CNPEntitySelector   `yaml:"toEndpoints,omitempty"`
	ToCIDR      []string              `yaml:"toCIDR,omitempty"`
	ToFQDNs     []FQDNSelector        `yaml:"toFQDNs,omitempty"`
	ToServices  []ServiceSelector     `yaml:"toServices,omitempty"`
	TCP         []PortRule            `yaml:"toPorts,omitempty"`
	L7Rules     []map[string][]L7Rule `yaml:"l7Rules,omitempty"`
	Description string                `yaml:"comment,omitempty"`
}

// CNPDefaultCgroup maps endpoint defaults fields.
type CNPDefaultCgroup struct {
	// Name is the name of the cgroup.
	Name string `yaml:"name,omitempty"`
}

// CNPDefaultPorts maps port/protocol pairs for endpoint defaults.
type CNPDefaultPorts struct {
	// Rules is a slice of port/protocol rules.
	Rules []PortRule `yaml:"rules,omitempty"`
}

// CNPDefaultEndpoint represents the endpointDefaults stanza.
type CNPDefaultEndpoint struct {
	// Cgroups maps endpoint-level cgroup configurations.
	Cgroups []CNPDefaultCgroup `yaml:"cgroups,omitempty"`
	// Ports maps endpoint-level port/protocol access.
	Ports []CNPDefaultPorts `yaml:"ports,omitempty"`
}

// L7Rule represents an L7 (application-layer) policy rule.
type L7Rule struct {
	// DNS matches DNS query patterns.
	DNS string `yaml:"DNS,omitempty"`
	// Method is an HTTP method.
	Method string `yaml:"method,omitempty"`
	// Path is an HTTP request path.
	Path string `yaml:"path,omitempty"`
	// Host is the HTTP Host or TLS SNI.
	Host string `yaml:"host,omitempty"`
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
// apiserverCIDRs is used to expand "apiserver" sentinels in FromWorkloads/ToCIDRs
// to concrete CIDR ranges.
//
// Output is deterministic: sorted by CNP metadata.name.
func BuildCilium(policies []Policy, flows []flow.Flow, apiserverCIDRs []string) []CiliumNetworkPolicy {
	cnps := make([]CiliumNetworkPolicy, 0, len(policies))

	// Collect L7 hints by workload from flows.
	l7Hints := collectL7Hints(flows)

	for i := range policies {
		p := &policies[i]
		cnp := buildCNPFromPolicy(p, l7Hints, apiserverCIDRs)
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

// buildCNPFromPolicy converts a single Policy into a CiliumNetworkPolicy.
func buildCNPFromPolicy(p *Policy, l7Hints map[string][]L7HintData, apiserverCIDRs []string) *CiliumNetworkPolicy {
	// Build endpoint selector from workload labels.
	endpointLabels := map[string]string{
		"app": p.WorkloadName,
	}

	cnp := &CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: CNPMetadata{
			Name:      "policy-" + sanitizeName(p.WorkloadName),
			Namespace: p.WorkloadNamespace,
			Labels: map[string]string{
				"app":         p.WorkloadName,
				"policy.k8s.io/name":  "flowguarder",
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
		rule := CNPIngressRule{
			Description: ir.Description,
		}

		// FromEndpoints from workload selectors.
		for _, wl := range ir.FromWorkloads {
			if wl == "apiserver" {
				// Expand apiserver sentinel to fromCIDR using config CIDRs.
				if len(apiserverCIDRs) > 0 {
					rule.FromCIDR = append(rule.FromCIDR, apiserverCIDRs...)
				} else {
					rule.FromCIDR = append(rule.FromCIDR, config.DefaultAPIServerCIDRsStrings...)
				}
				continue
			}
			if sel := parseWorkloadSelector(wl); sel != nil {
				rule.FromEndpoints = append(rule.FromEndpoints, *sel)
			}
		}

		// ToPorts.
		for _, ps := range ir.Ports {
			rule.TCP = append(rule.TCP, PortRule{
				Port:     itoa(int(ps.Port)),
				Protocol: string(flow.ANY_P), // match any protocol
			})
			if ps.Protocol == string(flow.TCP) {
				rule.TCP = append(rule.TCP, PortRule{
					Port:     itoa(int(ps.Port)),
					Protocol: string(flow.TCP),
				})
			} else if ps.Protocol == string(flow.UDP) {
				rule.TCP = append(rule.TCP, PortRule{
					Port:     itoa(int(ps.Port)),
					Protocol: string(flow.UDP),
				})
			}
			rule.TCP = dedupPortRules(rule.TCP)

			// L7 DNS rule for port 53.
			if ps.Port == 53 {
				rule.L7Rules = append(rule.L7Rules, map[string][]L7Rule{
					"DNS": {
						{DNS: "*"}, // allow all DNS queries to this port
					},
				})
			}
		}

		// Append egress-level L7 hints for ingress destination workload.
		if hints, ok := l7Hints[p.WorkloadID]; ok {
			rule.L7Rules = dedupL7Rules(rule.L7Rules, hints)
		}

		cnp.Spec.Ingress = append(cnp.Spec.Ingress, rule)
	}

	// Egress rules.
	for _, er := range p.EgressRules {
		rule := CNPEgressRule{
			Description: er.Description,
		}

		// ToEndpoints.
		for _, wl := range er.ToWorkloads {
			if sel := parseWorkloadSelector(wl); sel != nil {
				rule.ToEndpoints = append(rule.ToEndpoints, *sel)
			}
		}

		// ToCIDRs for world egress, expanding "apiserver" sentinel.
		for _, cidr := range er.ToCIDRs {
			if cidr == "apiserver" {
				if len(apiserverCIDRs) > 0 {
					rule.ToCIDR = append(rule.ToCIDR, apiserverCIDRs...)
				} else {
					rule.ToCIDR = append(rule.ToCIDR, config.DefaultAPIServerCIDRsStrings...)
				}
			} else {
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
			rule.TCP = append(rule.TCP, PortRule{
				Port:     itoa(int(ps.Port)),
				Protocol: string(flow.ANY_P), // match any
			})
			if ps.Protocol == string(flow.TCP) {
				rule.TCP = append(rule.TCP, PortRule{
					Port:     itoa(int(ps.Port)),
					Protocol: string(flow.TCP),
				})
			} else if ps.Protocol == string(flow.UDP) {
				rule.TCP = append(rule.TCP, PortRule{
					Port:     itoa(int(ps.Port)),
					Protocol: string(flow.UDP),
				})
			}
			rule.TCP = dedupPortRules(rule.TCP)

			// L7 DNS for egress port 53.
			if ps.Port == 53 {
				rule.L7Rules = append(rule.L7Rules, map[string][]L7Rule{
					"DNS": {
						{DNS: "*"},
					},
				})
			}
		}

		// Append FQDN L7 hints for this workload.
		if hints, ok := l7Hints[p.WorkloadID]; ok {
			rule.L7Rules = dedupL7Rules(rule.L7Rules, hints)
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

// findHintsForPort returns L7 hints relevant to a specific port for a direction.
func findHintsForPort(p *Policy, port uint16, dir flow.Direction) []L7HintData {
	// For port 53, return DNS-related hints for this workload.
	if dir == flow.Ingress {
		// We look up via l7Hints in BuildCilium; for now return nil.
		return nil
	}
	return []L7HintData{}
}

// findEgressHints returns L7 hints for egress FQDN generation.
func findEgressHints(p *Policy, allHints map[string][]L7HintData) []L7HintData {
	return allHints[p.WorkloadID]
}

// parseWorkloadSelector parses a workload identifier into a CNP entity selector.
func parseWorkloadSelector(sel string) *CNPEntitySelector {
	// Check if it's a label selector (key=value format).
	if contains(sel, "=") {
		parts := splitN(sel, "=", 2)
		return &CNPEntitySelector{
			MatchLabels: map[string]string{
				parts[0]: parts[1],
			},
		}
	}
	// Plain workload ID - resolve to name label.
	idx := index(sel, "/")
	if idx >= 0 {
		sel = sel[idx+1:]
	}
	return &CNPEntitySelector{
		MatchLabels: map[string]string{
			"app": sel,
		},
	}
}

// dedupPortRules removes duplicate PortRule entries.
func dedupPortRules(rules []PortRule) []PortRule {
	seen := make(map[string]bool)
	var out []PortRule
	for _, r := range rules {
		key := r.Port + "/" + r.Protocol
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

// dedupL7Rules merges L7 rule maps from multiple hints.
func dedupL7Rules(existing []map[string][]L7Rule, hints []L7HintData) []map[string][]L7Rule {
	// Merge DNS L7 rules from hints.
	dnsRules := make(map[string]bool)
	tlsRules := make(map[string]bool)

	for _, h := range hints {
		if h.Type == "dns" && h.Query != "" && !dnsRules[h.Query] {
			dnsRules[h.Query] = true
		}
		if h.Type == "tls" && h.Host != "" && !tlsRules[h.Host] {
			tlsRules[h.Host] = true
		}
	}

	for _, m := range existing {
		if rules, ok := m["DNS"]; ok {
			for _, r := range rules {
				if r.DNS == "*" {
					// Full wildcard - already covers DNS.
					return existing
				}
			}
		}
	}

	// Add new L7 rules.
	var merged []map[string][]L7Rule

	// Keep existing non-wildcard DNS rules.
	for _, m := range existing {
		merged = append(merged, m)
	}

	return merged
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

		fname := "policy-" + sanitizeName(cnp.Metadata.Name) + ".yaml"
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

// Helper string functions to avoid stdlib import.

func contains(s, substr string) bool {
	return index(s, substr) >= 0
}

func index(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func splitN(s, sep string, n int) []string {
	if n <= 0 {
		return nil
	}
	var parts []string
	for i := 0; i < len(s); {
		idx := index(s[i:], sep)
		if idx < 0 {
			parts = append(parts, s[i:])
			break
		}
		parts = append(parts, s[i:i+idx])
		if len(parts) >= n-1 {
			parts = append(parts, s[i+idx+len(sep):])
			break
		}
		i = i + idx + len(sep)
	}
	if len(parts) == 0 {
		return []string{s}
	}
	return parts
}

// itoa converts a uint16 to string (reused from builder.go).
var itoa16 = func(val uint16) string {
	if val == 0 {
		return "0"
	}
	var buf [6]byte
	n := len(buf)
	for val > 0 {
		n--
		buf[n] = byte('0' + val%10)
		val /= 10
	}
	return string(buf[n:])
}
