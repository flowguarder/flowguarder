package simulate

import (
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/policy"
)

const dnsPort = 53

// EvaluateCiliumNetworkPolicy evaluates a simulated flow against
// CiliumNetworkPolicy manifests and returns the effective verdict for both
// ingress and egress directions.
//
// Parameters:
//
//	src/dst: source and destination endpoints of the flow.
//	traffic: L4/L7 flow description.
//	policies: all loaded policies. The function filters for
//	Kind=="CiliumNetworkPolicy" with Cilium != nil internally.
//	l7: optional L7 override. When non-nil and has L7Name or L7Pattern set,
//	those values replace traffic's corresponding fields for L7 matching.
//
// Returns a Result with Ingress and Egress verdicts. MatchingFiles is sorted
// and deduplicated policy file paths that produced the verdicts (allow:
// files whose rule matched; deny: covering files; undetermined: nil).
func EvaluateCiliumNetworkPolicy(
	src, dst Endpoint,
	traffic Traffic,
	policies []LoadedPolicy,
	l7 *Traffic,
) Result {
	var res Result

	ingV, ingFiles := evalDir(src, dst, traffic, policies, l7, ingress)
	egV, egFiles := evalDir(src, dst, traffic, policies, l7, egress)

	res.Ingress = ingV
	res.Egress = egV
	res.MatchingFiles = mergeFiles(ingFiles, egFiles)
	return res
}

// ---------------------------------------------------------------------------
// cnRule: flattened ingress/egress rule fields.
// No dead fields. Each field comes from the real CNP struct.
// ---------------------------------------------------------------------------

type cnRule struct {
	fromEndpoints []policy.CNPEntitySelector
	toEndpoints   []policy.CNPEntitySelector
	fromCIDR      []string
	toCIDR        []string
	fromEntities  []string
	toEntities    []string
	toFQDNs       []policy.FQDNSelector
	toServices    []policy.ServiceSelector
	toPorts       []policy.CNPToPorts
}

func extractIngress(rs []policy.CNPIngressRule) []cnRule {
	out := make([]cnRule, len(rs))
	for i, r := range rs {
		out[i] = cnRule{
			fromEndpoints: r.FromEndpoints,
			fromCIDR:      r.FromCIDR,
			fromEntities:  r.FromEntities,
			toPorts:       r.ToPorts,
		}
	}
	return out
}

func extractEgress(rs []policy.CNPEgressRule) []cnRule {
	out := make([]cnRule, len(rs))
	for i, r := range rs {
		out[i] = cnRule{
			toEndpoints: r.ToEndpoints,
			toCIDR:      r.ToCIDR,
			toEntities:  r.ToEntities,
			toFQDNs:     r.ToFQDNs,
			toServices:  r.ToServices,
			toPorts:     r.ToPorts,
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// direction type (parallel eval_np.go uses a separate npDir type).
// ---------------------------------------------------------------------------

type direction int

const (
	ingress direction = 0
	egress  direction = 1
)

// evalDir returns (verdict, file list) for one direction.
// allow: files whose rule matched.
// deny: files of all covering policies in that direction.
// undetermined: nil.
func evalDir(src, dst Endpoint, traffic Traffic, policies []LoadedPolicy, l7in *Traffic, dir direction) (Verdict, []string) {
	var scope, peer Endpoint
	if dir == ingress {
		scope, peer = dst, src
	} else {
		scope, peer = src, dst
	}
	eff := effectiveTraffic(traffic, l7in)

	var covered bool
	var coveringFiles []string
	var allowFiles []string

	for i := range policies {
		p := &policies[i]
		if p.Kind != "CiliumNetworkPolicy" || p.Cilium == nil {
			continue
		}
		cnp := p.Cilium
		spec := &cnp.Spec

		// Namespace scoping.
		if cnp.Metadata.Namespace != "" && cnp.Metadata.Namespace != scope.Namespace {
			continue
		}

		// endpointSelector selects scope endpoint?
		if !matchSel(spec.EndpointSelector, scope) {
			continue
		}

		var rules []cnRule
		if dir == egress {
			if len(spec.Egress) == 0 {
				continue
			}
			rules = extractEgress(spec.Egress)
		} else {
			if len(spec.Ingress) == 0 {
				continue
			}
			rules = extractIngress(spec.Ingress)
		}
		covered = true

		if p.File != "" {
			coveringFiles = append(coveringFiles, p.File)
		}

		// Check each rule.
		for j := range rules {
			if dirMatches(&rules[j], peer, eff, dir) {
				allowFiles = append(allowFiles, p.File)
			}
		}
	}

	if len(allowFiles) > 0 {
		return VerdictAllow, allowFiles
	}
	if covered {
		return VerdictDeny, coveringFiles
	}
	return VerdictUndetermined, nil
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func effectiveTraffic(t Traffic, l7in *Traffic) Traffic {
	if l7in != nil && (l7in.L7Name != "" || l7in.L7Pattern != "") {
		e := t
		if l7in.L7Name != "" {
			e.L7Name = l7in.L7Name
		}
		if l7in.L7Pattern != "" {
			e.L7Pattern = l7in.L7Pattern
		}
		return e
	}
	return t
}

func matchSel(s policy.CNPEntitySelector, ep Endpoint) bool {
	ml := s.MatchLabels
	if ml == nil {
		return true
	}
	return sub(ml, ep.Labels)
}

func sub(sub, sup map[string]string) bool {
	for k, v := range sub {
		if sup[k] != v {
			return false
		}
	}
	return true
}

func dirMatches(r *cnRule, ep Endpoint, eff Traffic, dir direction) bool {
	if dir == ingress {
		return matchIngress(r, ep, eff)
	}
	return matchEgress(r, ep, eff)
}

// matchIngress checks FROM constraints + toPorts.
func matchIngress(r *cnRule, ep Endpoint, eff Traffic) bool {
	if len(r.fromEndpoints) > 0 && !anyEp(r.fromEndpoints, ep) {
		return false
	}
	if len(r.fromCIDR) > 0 {
		if ep.IP == "" || !hasCIDR(ep.IP, r.fromCIDR) {
			return false
		}
	}
	if len(r.fromEntities) > 0 && !hasEnt(ep.Entity, r.fromEntities) {
		return false
	}
	return matchPorts(r.toPorts, eff)
}

// matchEgress checks TO constraints + toPorts.
func matchEgress(r *cnRule, ep Endpoint, eff Traffic) bool {
	if len(r.toEndpoints) > 0 && !anyEp(r.toEndpoints, ep) {
		return false
	}
	if len(r.toCIDR) > 0 {
		if ep.IP == "" || !hasCIDR(ep.IP, r.toCIDR) {
			return false
		}
	}
	if len(r.toEntities) > 0 && !hasEnt(ep.Entity, r.toEntities) {
		return false
	}
	if len(r.toFQDNs) > 0 && isL7(eff) {
		if !matchFQDN(eff, r.toFQDNs) {
			return false
		}
	}
	if len(r.toServices) > 0 && !matchSvc(r.toServices, ep) {
		return false
	}
	return matchPorts(r.toPorts, eff)
}

func anyEp(sels []policy.CNPEntitySelector, ep Endpoint) bool {
	for _, s := range sels {
		if matchSel(s, ep) {
			return true
		}
	}
	return false
}

func hasCIDR(ip string, list []string) bool {
	p, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range list {
		pr, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if pr.Contains(p) {
			return true
		}
	}
	return false
}

func hasEnt(entity string, list []string) bool {
	if entity == "" {
		return false
	}
	for _, e := range list {
		if e == entity {
			return true
		}
	}
	return false
}

// isL7 reports whether L7 context (name or pattern) is present.
func isL7(eff Traffic) bool {
	return eff.L7Name != "" || eff.L7Pattern != ""
}

// matchFQDN validates each FQDNSelector entry against eff.L7Name.
// MatchName: exact match.  MatchPattern: path.Match glob.
func matchFQDN(eff Traffic, fqdns []policy.FQDNSelector) bool {
	for _, f := range fqdns {
		if f.MatchName != "" && f.MatchName == eff.L7Name {
			return true
		}
		if f.MatchPattern != "" {
			if m, _ := path.Match(f.MatchPattern, eff.L7Name); m {
				return true
			}
		}
	}
	return false
}

func matchSvc(sels []policy.ServiceSelector, ep Endpoint) bool {
	for _, s := range sels {
		ns := s.Namespace == "" || s.Namespace == ep.Namespace
		app := ep.Labels["app"]
		if app == "" {
			app = ep.Labels["name"]
		}
		if ns && (app == "" || app == s.Name) {
			return true
		}
	}
	return false
}

// matchPorts checks port+protocol + optional DNS L7 rules on each toPorts entry.
// traffic.Port == 0 → any-port match (return true immediately).
// CNPRules only has DNS; non-DNS traffic with DNS rules → the entry cannot match
// (HTTP/Kafka L7 is not representable in CNPRules), so we continue to the next
// toPorts entry instead of returning false for the whole rule.
func matchPorts(ports []policy.CNPToPorts, eff Traffic) bool {
	if len(ports) == 0 || eff.Port == 0 {
		return true
	}

	for _, tp := range ports {
		r := tp.Rules

		// Empty ports and no L7 rules → accepts any traffic.
		if (len(tp.Ports) == 0) && r == nil {
			return true
		}

		// Port/protocol match.
		proto := strings.ToUpper(eff.Protocol)
		portOk := false
		for _, pr := range tp.Ports {
			pUp := strings.ToUpper(pr.Protocol)
			if pUp != "" && pUp != proto {
				continue
			}
			if pr.Port == "" {
				portOk = true
				break
			}
			v, err := strconv.Atoi(pr.Port)
			if err != nil {
				continue
			}
			if v == eff.Port {
				portOk = true
				break
			}
		}
		if !portOk {
			continue // try next toPorts entry
		}

		// L4 port+protocol matched; gate on L7 if DNS rules are present.
		if r != nil && len(r.DNS) > 0 {
			if !isDNS(eff) {
				// DNS rules only apply to DNS traffic; non-DNS cannot match.
				continue // try next toPorts entry
			}
			return dnsOK(r.DNS, eff)
		}

		// Port matched, no L7 rules on this entry → allow.
		return true
	}

	// No toPorts entry satisfied all constraints.
	return false
}

func isDNS(t Traffic) bool { return t.Port == dnsPort }

func dnsOK(drs []policy.CNPDNSRule, eff Traffic) bool {
	if !isL7(eff) {
		return true
	}
	for _, d := range drs {
		if d.MatchName != "" && d.MatchName == eff.L7Name {
			return true
		}
		if d.MatchPattern != "" {
			if m, _ := path.Match(d.MatchPattern, eff.L7Name); m {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// File helpers.
// ---------------------------------------------------------------------------

func mergeFiles(a, b []string) []string {
	all := make([]string, 0, len(a)+len(b))
	all = append(all, a...)
	all = append(all, b...)
	seen := make(map[string]struct{}, len(all))
	out := make([]string, 0, len(all))
	for _, f := range all {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			out = append(out, f)
		}
	}
	// Return nil, not [], when there are no matches.
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
