package flow

import (
	"fmt"
	"time"
)

// Verdict represents the action taken on a network flow.
type Verdict string

const (
	// Forwarded indicates the flow was allowed to pass through.
	Forwarded Verdict = "FORWARDED"
	// Dropped indicates the flow packet was discarded.
	Dropped Verdict = "DROPPED"
	// Audit indicates the flow was only logged for observation.
	Audit Verdict = "AUDIT"
	// Redirected indicates the flow was redirected to another destination.
	Redirected Verdict = "REDIRECTED"
	// Denied indicates the flow was explicitly denied by policy.
	Denied Verdict = "DENIED"
	// Allow indicates the flow was explicitly allowed.
	Allow Verdict = "ALLOW"
)

// IsAllowed reports whether the verdict permits the flow.
func (v Verdict) IsAllowed() bool {
	switch v {
	case Forwarded, Allow, Redirected:
		return true
	default:
		return false
	}
}

// Protocol represents a Layer 4 protocol.
type Protocol string

const (
	TCP  Protocol = "TCP"
	UDP  Protocol = "UDP"
	ICMP Protocol = "ICMP"
	SCTP Protocol = "SCTP"
	Any  Protocol = "ANY"
)

// Direction represents the traffic direction relative to a workload.
type Direction string

const (
	// Ingress indicates traffic entering a workload.
	Ingress Direction = "INGRESS"
	// Egress indicates traffic leaving a workload.
	Egress Direction = "EGRESS"
	// Internal indicates traffic between pods within the same workload or node.
	Internal Direction = "INTERNAL"
)

// PeerType classifies the nature of a flow's peer relationship.
type PeerType string

const (
	PodPod        PeerType = "pod-pod"
	IngressWorld  PeerType = "ingress-world"
	EgressWorld   PeerType = "egress-world"
	DNS           PeerType = "dns"
	KubeAPIServer PeerType = "kube-apiserver"
	Unknown       PeerType = "unknown"
)

// Endpoint describes a network endpoint (typically a Kubernetes pod).
type Endpoint struct {
	Namespace      string
	PodName        string
	ServiceAccount string
	Labels         map[string]string
	IP             string
	// Service is a Hubble-style service hint (e.g. "default/kubernetes" or
	// "prod/api-server:8080") that can be used to resolve a Kubernetes Service
	// name without cluster access. Populated by the Hubble parser from the
	// JSON "destination/service" field.
	Service string
}

// Layer4 describes a Layer 4 (transport) flow endpoint.
type Layer4 struct {
	SourcePort uint16
	DestPort   uint16
	Protocol   Protocol
}

// L7Hint holds optional Layer 7 (application) hints extracted from the flow.
// These enrich the flow with protocol-level context such as DNS queries, HTTP
// method/path, or TLS SNI names without requiring a full L7 parser.
type L7Hint struct {
	// Type distinguishes the application protocol: dns, http, or tls.
	Type string // "dns", "http", or "tls"
	// Query holds a DNS query name (e.g. "service.prod.svc.cluster.local").
	Query string
	// Method holds the HTTP method (e.g. "GET", "POST").
	Method string
	// Path holds the HTTP request path (e.g. "/api/v1/pods").
	Path string
	// Host holds the HTTP Host header or the SNI name for TLS.
	Host string
}

// Flow represents a unified network flow observed from any CNI source.
//
// All fields are optional except those explicitly validated by Validate().
// Parsers populate this struct from source-specific formats (Hubble, Calico,
// etc.). Analysis code operates on this canonical form.
type Flow struct {
	// Time is the timestamp when the flow was observed.
	Time time.Time
	// Source is the originating endpoint.
	Source Endpoint
	// Destination is the target endpoint.
	Destination Endpoint
	// Layer4 contains Layer 4 transport info.
	Layer4 Layer4
	// Verdict is the action taken on the flow.
	Verdict Verdict
	// Direction is the traffic direction relative to Source.
	Direction Direction
	// PeerType classifies the relationship between Source and Destination.
	PeerType PeerType
	// L7 holds optional application-level hints.
	L7 *L7Hint
	// Bytes is the number of bytes observed in this flow.
	Bytes uint64
	// Packets is the number of packets observed in this flow.
	Packets uint64
	// SourceLabels are labels from the Source pod (shorthand for Source.Labels).
	SourceLabels map[string]string
	// DestLabels are labels from the Destination pod (shorthand for Destination.Labels).
	DestLabels map[string]string
	// IsReply indicates whether this flow is a reply/return packet.
	IsReply bool
	// PolicyName is the name of the network policy that matched this flow.
	// Populated by Hubble (first of policy_names), Calico (policy_name), and
	// Goldmane (first enforced policy, preferring Deny action).
	PolicyName string
	// DropReason is an optional human-readable reason why a dropped flow was
	// denied. Populated by the Hubble parser from the "drop_reason" field.
	DropReason string
}

// Validate returns an error if required fields are missing or empty.
// Required fields: Source.IP, Destination.IP, Time (zero check),
// Verdict, and Direction.
func (f Flow) Validate() error {
	if f.Source.IP == "" {
		return fmt.Errorf("flow: missing required field Source.IP")
	}
	if f.Destination.IP == "" {
		return fmt.Errorf("flow: missing required field Destination.IP")
	}
	if f.Time.IsZero() {
		return fmt.Errorf("flow: missing required field Time")
	}
	if f.Verdict == "" {
		return fmt.Errorf("flow: missing required field Verdict")
	}
	if f.Direction == "" {
		return fmt.Errorf("flow: missing required field Direction")
	}
	return nil
}
