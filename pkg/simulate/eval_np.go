package simulate

import (
	"net/netip"
	"sort"
	"strings"

	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// EvaluateNetworkPolicy evaluates a simulated flow against
// NetworkPolicy manifests and returns the effective verdict for both
// ingress and egress directions.
//
// Parameters:
//
//	src/dst:  source and destination endpoints of the flow.
//	traffic:  L4/L7 flow description.
//	policies: all loaded policies. The function filters for
//	Kind=="NetworkPolicy" with Network != nil internally.
//
// Returns a Result with Ingress and Egress verdicts. MatchingFiles are
// sorted and deduplicated policy file paths that produced the verdicts.
func EvaluateNetworkPolicy(src, dst Endpoint, traffic Traffic, policies []LoadedPolicy) Result {
	res := Result{}

	// Filter to NetworkPolicy-only.
	npPolicies := filterNetPol(policies)

	// Ingress: policies targeting dst.
	inRes := evalNPDir(src, dst, traffic, npPolicies, npIngress)
	res.Ingress = inRes.verdict
	res.MatchingFiles = inRes.files

	// Egress: policies targeting src.
	enRes := evalNPDir(dst, src, traffic, npPolicies, npEgress)
	res.Egress = enRes.verdict
	res.MatchingFiles = appendAndDedup(res.MatchingFiles, enRes.files)

	return res
}

// npDir is a direction constant for the NetworkPolicy evaluator.
// It lives in this file only to avoid colliding with eval_cnp.go's direction type.
type npDir int

const (
	npIngress npDir = 0
	npEgress  npDir = 1
)

// npDirResult holds the verdict and file list for a single direction.
type npDirResult struct {
	verdict Verdict
	files   []string // non-nil, may contain duplicates before dedup
}

func filterNetPol(policies []LoadedPolicy) []LoadedPolicy {
	out := make([]LoadedPolicy, 0, len(policies))
	for i := range policies {
		if policies[i].Kind == "NetworkPolicy" && policies[i].Network != nil {
			out = append(out, policies[i])
		}
	}
	return out
}

func evalNPDir(src, dst Endpoint, traffic Traffic, policies []LoadedPolicy, dir npDir) npDirResult {
	fileList := make([]string, 0)
	allowFiles := make([]string, 0)
	covered := false

	for i := range policies {
		pol := policies[i]
		np := pol.Network
		spec := &np.Spec

		// Scope: same namespace.
		if np.Namespace != "" && np.Namespace != dst.Namespace {
			continue
		}

		// Pod selector must select the targeted endpoint.
		if !podSelectorMatches(spec.PodSelector, dst) {
			continue
		}

		var rules []npRule
		switch dir {
		case npIngress:
			if spec.Ingress == nil {
				continue
			}
			if len(spec.Ingress) == 0 {
				// Default-deny: covered, no rules to match.
				fileList = appendSafely(fileList, pol.File)
				covered = true
				continue
			}
			rules = toNPIngressRules(spec.Ingress)
		case npEgress:
			if spec.Egress == nil {
				continue
			}
			if len(spec.Egress) == 0 {
				// Default-deny: covered, no rules to match.
				fileList = appendSafely(fileList, pol.File)
				covered = true
				continue
			}
			rules = toNPEgressRules(spec.Egress)
		}

		// Covered by this policy; record file for deny verdict.
		covered = true
		fileList = appendSafely(fileList, pol.File)

		// Any matching rule → allow for this policy.
		for _, rule := range rules {
			if ruleMatches(rule, src, dst, traffic, dir, pol.File) {
				allowFiles = appendSafely(allowFiles, pol.File)
				break
			}
		}
	}

	// All policies evaluated.
	if len(allowFiles) > 0 {
		return npDirResult{verdict: VerdictAllow, files: dedupSorted(allowFiles)}
	}
	if covered {
		return npDirResult{verdict: VerdictDeny, files: dedupSorted(fileList)}
	}
	return npDirResult{verdict: VerdictUndetermined, files: nil}
}

func appendSafely(dst []string, src string) []string {
	if src == "" {
		return dst
	}
	return append(dst, src)
}

type npRule struct {
	peers []v1.NetworkPolicyPeer
	ports []v1.NetworkPolicyPort
}

func toNPIngressRules(rs []v1.NetworkPolicyIngressRule) []npRule {
	out := make([]npRule, 0, len(rs))
	for _, r := range rs {
		out = append(out, npRule{peers: r.From, ports: r.Ports})
	}
	return out
}

func toNPEgressRules(rs []v1.NetworkPolicyEgressRule) []npRule {
	out := make([]npRule, 0, len(rs))
	for _, r := range rs {
		out = append(out, npRule{peers: r.To, ports: r.Ports})
	}
	return out
}

// ---------------------------------------------------------------------------
// Pod selectors
// ---------------------------------------------------------------------------

// podSelectorMatches checks whether a label selector selects a pod.
// Nil or empty selector matches everything.
func podSelectorMatches(selector metav1.LabelSelector, ep Endpoint) bool {
	if isLabelSelectorEmpty(&selector) {
		return true
	}
	return matchLabelSelector(selector, ep.Labels)
}

func isLabelSelectorEmpty(sel *metav1.LabelSelector) bool {
	if sel == nil {
		return true
	}
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func matchLabelSelector(selector metav1.LabelSelector, labels map[string]string) bool {
	for k, v := range selector.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, expr := range selector.MatchExpressions {
		if !matchExpression(expr, labels) {
			return false
		}
	}
	return true
}

func matchExpression(expr metav1.LabelSelectorRequirement, labels map[string]string) bool {
	val, exists := labels[expr.Key]
	switch expr.Operator {
	case metav1.LabelSelectorOpIn:
		if !exists {
			return false
		}
		for _, v := range expr.Values {
			if val == v {
				return true
			}
		}
		return false
	case metav1.LabelSelectorOpNotIn:
		if !exists {
			return true
		}
		for _, v := range expr.Values {
			if val == v {
				return false
			}
		}
		return true
	case metav1.LabelSelectorOpExists:
		return exists
	case metav1.LabelSelectorOpDoesNotExist:
		return !exists
	default:
		return false
	}
}

func ruleMatches(rule npRule, srcEp, scopeEp Endpoint, traffic Traffic, _ npDir, polFile string) bool {
	if len(rule.peers) == 0 {
		return portMatches(rule.ports, traffic)
	}
	target := &srcEp
	for _, peer := range rule.peers {
		if peerMatches(peer, target, traffic, scopeEp.Namespace) {
			if portMatches(rule.ports, traffic) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Peer matching
// ---------------------------------------------------------------------------

func peerMatches(peer v1.NetworkPolicyPeer, target *Endpoint, traffic Traffic, policyNS string) bool {
	hasPod := peer.PodSelector != nil
	hasNS := peer.NamespaceSelector != nil
	hasIP := peer.IPBlock != nil

	// No constraints → matches everything.
	if !hasPod && !hasNS && !hasIP {
		return true
	}

	// IPBlock standalone.
	if hasIP && !hasPod && !hasNS {
		return ipBlockMatches(peer.IPBlock, target)
	}

	// IPBlock + Pod/NS is invalid k8s; treat as no-match.
	if hasIP && (hasPod || hasNS) {
		return false
	}

	// NamespaceSelector-only.
	if !hasPod && hasNS {
		return nsMatches(*peer.NamespaceSelector, target.Namespace)
	}

	// PodSelector-only: same-namespace enforcement.
	if hasPod && !hasNS {
		if target.Namespace != policyNS {
			return false
		}
		return matchLabelSelector(*peer.PodSelector, target.Labels)
	}

	// Both PodSelector and NamespaceSelector AND.
	if !matchLabelSelector(*peer.PodSelector, target.Labels) {
		return false
	}
	if !nsMatches(*peer.NamespaceSelector, target.Namespace) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Namespace matching (k8s NamespaceSelector)
// ---------------------------------------------------------------------------

func nsMatches(selector metav1.LabelSelector, nsName string) bool {
	if isLabelSelectorEmpty(&selector) {
		// empty or nil selector matches ALL namespaces.
		return true
	}

	// Standard label: kubernetes.io/metadata.name = namespace name.
	if v, ok := selector.MatchLabels["kubernetes.io/metadata.name"]; ok {
		return nsName == v
	}
	// Fallback: plain "name" key matches namespace name directly.
	if v, ok := selector.MatchLabels["name"]; ok {
		return nsName == v
	}

	// Match expressions on the metadata.name key.
	for _, expr := range selector.MatchExpressions {
		if expr.Key == "kubernetes.io/metadata.name" {
			if !nsExprMatches(expr, nsName) {
				return false
			}
		}
	}
	return true
}

func nsExprMatches(expr metav1.LabelSelectorRequirement, val string) bool {
	switch expr.Operator {
	case metav1.LabelSelectorOpIn:
		for _, v := range expr.Values {
			if val == v {
				return true
			}
		}
		return false
	case metav1.LabelSelectorOpNotIn:
		for _, v := range expr.Values {
			if val == v {
				return false
			}
		}
		return true
	case metav1.LabelSelectorOpExists:
		return true
	case metav1.LabelSelectorOpDoesNotExist:
		return false
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// IPBlock
// ---------------------------------------------------------------------------

func ipBlockMatches(block *v1.IPBlock, target *Endpoint) bool {
	if target == nil || target.IP == "" {
		return false
	}

	cidr, cidrErr := netip.ParsePrefix(block.CIDR)
	if cidrErr != nil {
		return false
	}

	ip, ipErr := netip.ParseAddr(target.IP)
	if ipErr != nil {
		return false
	}

	if !cidr.Contains(ip) {
		return false
	}

	for _, except := range block.Except {
		ep, err := netip.ParsePrefix(except)
		if err != nil {
			continue
		}
		if ep.Contains(ip) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Port matching
// ---------------------------------------------------------------------------

func portMatches(ports []v1.NetworkPolicyPort, traffic Traffic) bool {
	if len(ports) == 0 {
		return true
	}
	if traffic.Port == 0 {
		return true
	}

	protoUp := strings.ToUpper(traffic.Protocol)

	for i := range ports {
		p := &ports[i]

		// nil protocol + (nil or zero) port → match any.
		if p.Protocol == nil && (p.Port == nil ||
			(p.Port.Type == intstr.Int && p.Port.IntVal == 0)) {
			return true
		}

		// Protocol must match if specified.
		if p.Protocol != nil {
			if strings.ToUpper(string(*p.Protocol)) != protoUp {
				continue
			}
		}

		// Port must match if specified.
		if p.Port != nil {
			switch p.Port.Type {
			case intstr.Int:
				if int(p.Port.IntVal) == traffic.Port {
					return true
				}
			case intstr.String:
				if strings.EqualFold(p.Port.StrVal, traffic.Protocol) {
					return true
				}
			}
		} else {
			// Port is nil → matches any port.
			return true
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

func appendAndDedup(dst, src []string) []string {
	seen := make(map[string]struct{}, len(src))
	for _, f := range dst {
		seen[f] = struct{}{}
	}
	for _, f := range src {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			dst = append(dst, f)
		}
	}
	sort.Strings(dst)
	return dst
}

func dedupSorted(files []string) []string {
	if len(files) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(files))
	out := make([]string, 0, len(files))
	for _, f := range files {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}
