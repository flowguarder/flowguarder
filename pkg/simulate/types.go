// Package simulate provides types and a YAML policy loader for the
// flowGuarder traffic simulation feature.
//
// Types defined here are consumed evaluator plugins (Wave 3/4) to reason
// whether a simulated L4/L7 flow is allowed, denied, or undetermined
// by a directory of hand-written and/or flowGuarder-generated policies.
package simulate

import (
	"github.com/flowguarder/flowguarder/pkg/policy"
	networkingv1 "k8s.io/api/networking/v1"
)

// Endpoint describes one side of the simulated traffic.
type Endpoint struct {
	Namespace string            // namespace of the workload/endpoint
	Labels    map[string]string // pod labels (namespace/name shorthand maps to {"app": name})
	IP        string            // optional literal IP or CIDR
	Entity    string            // optional Cilium reserved entity: world, cluster, host, remote-node, kube-apiserver
}

// Traffic describes L4/L7 attributes of the simulated flow.
type Traffic struct {
	Port      int    // 0 = any port
	Protocol  string // TCP, UDP, SCTP (normalized uppercase)
	L7Name    string // optional DNS name for L7 matching
	L7Pattern string // optional DNS wildcard pattern
}

// Verdict is the result of an evaluation pass.
type Verdict string

const (
	VerdictAllow        Verdict = "allow"
	VerdictDeny         Verdict = "deny"
	VerdictUndetermined Verdict = "undetermined"
)

// Result is the outcome of a simulation for a single flow.
type Result struct {
	Ingress       Verdict
	Egress        Verdict
	MatchingFiles []string // sorted, deduplicated policy file paths that produced the verdicts
}

// LoadedPolicy pairs a parsed policy with its source file path.
type LoadedPolicy struct {
	File string // path relative to the walked dir, e.g. "allow-ingress-np.yaml"
	Kind string // "NetworkPolicy" | "CiliumNetworkPolicy"
	// Network is set when Kind == "NetworkPolicy".
	Network *networkingv1.NetworkPolicy
	// Cilium is set when Kind == "CiliumNetworkPolicy".
	Cilium *policy.CiliumNetworkPolicy
}

// LoadError describes a per-file loading failure (does NOT abort other files).
type LoadError struct {
	File    string
	Message string
}
