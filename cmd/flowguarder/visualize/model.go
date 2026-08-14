// Package visualize extracts a deterministic directed graph from a slice of
// abstract [policy.Policy] objects for offline HTML policy visualization.
//
// The graph model is source-agnostic: it reads only the policy.Policy struct
// and never inspects the rendered NetworkPolicy or CiliumNetworkPolicy YAML.
package visualize

import (
	"cmp"
	"net"
	"slices"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/policy"
)

// --- Node kinds ----------------------------------------------------------

// NodeKind identifies the semantic category of a graph node.
type NodeKind string

const (
	// NamespaceKind is a Kubernetes namespace.
	// These nodes act as compound parents in HTML rendering.
	NamespaceKind NodeKind = "namespace"

	// WorkloadKind is a workload (Pod-level) inside a namespace.
	WorkloadKind NodeKind = "workload"

	// ReservedKind is a reserved peer entity such as "world" or "kube-apiserver".
	ReservedKind NodeKind = "reserved"

	// CIDRKind is an IP range (e.g. "10.0.0.0/8", "0.0.0.0/0").
	CIDRKind NodeKind = "cidr"

	// SelectorKind is an unresolvable label-format selector (e.g. "app=foo").
	SelectorKind NodeKind = "selector"
)

// --- Nodes ---------------------------------------------------------------

// Node represents a vertex in the policy graph.
type Node struct {
	// ID uniquely identifies this node across the entire graph.
	ID string
	// Label is the human-readable display label.
	Label string
	// Kind categorises the node.
	Kind NodeKind
	// Namespace is empty except for workload and reserved nodes.
	// For workloads it is the owning Kubernetes namespace.
	Namespace string
	// Parent is the ID of the owning namespace node (empty for namespace
	// nodes and reserved/selector/cidr nodes).  HTML renderers use this
	// to build nested [compound] groups.
	//
	// [compound]: https://graphviz.org/doc/info/shapes.html
	Parent string
}

// --- Edges ---------------------------------------------------------------

// Edge represents a directed edge in the policy graph.
type Edge struct {
	// Source is the ID of the source node.
	Source string
	// Target is the ID of the target node.
	Target string
	// Direction is "ingress" or "egress".
	Direction string
	// Protocol is the L4 protocol ("TCP", "UDP", "SCTP", "ICMP", "").
	Protocol string
	// Port is the L4 port number (0 means "all ports").
	Port uint16
	// Description is the rule description text.
	Description string
}

// --- Graph ---------------------------------------------------------------

// Graph is the complete policy graph extracted from one or more policies.
type Graph struct {
	Nodes []Node
	Edges []Edge
}

// --- Peer categorisation (deterministic, documented) ---------------------

// classifyPeer returns the ID and kind of a peer selector string.
//
// Rules (order matters — entity: checked first, label selectors before /):
//
//  1. Entry with "entity:" prefix → reserved node.
//  2. String containing "=" or "," → selector (label-format with key=value pairs).
//  3. CIDR-like string ("x.x.x.x/y") → cidr node.
//  4. Entry containing "/" → workload node (split on first "/").
//  5. Any other string → selector node.
func classifyPeer(s string) (id, label string, kind NodeKind) {
	// 1. Entity prefix → reserved.
	if strings.HasPrefix(s, "entity:") {
		return s, strings.TrimPrefix(s, "entity:"), ReservedKind
	}
	// 2. Label selector syntax (key=value pairs separated by ",") → selector.
	if strings.ContainsAny(s, "=,") {
		return s, s, SelectorKind
	}
	// 3. CIDR-like strings.
	if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		if isCIDRLike(parts[0]) {
			return s, s, CIDRKind
		}
	}
	// 4. Workload reference (namespace/name).
	if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		return s, parts[1], WorkloadKind
	}
	// 5. Bare name → selector.
	return s, s, SelectorKind
}

func isCIDRLike(s string) bool {
	return net.ParseIP(s) != nil
}

// --- Ensure helpers ------------------------------------------------------

func ensureNs(nodes map[string]*Node, ns string) {
	if _, ok := nodes[ns]; !ok {
		nodes[ns] = &Node{
			ID:    ns,
			Label: ns,
			Kind:  NamespaceKind,
		}
	}
}

func ensureWorkload(nodes map[string]*Node, ns, name string) *Node {
	ensureNs(nodes, ns)
	wID := ns + "/" + name
	if _, ok := nodes[wID]; !ok {
		nodes[wID] = &Node{
			ID:        wID,
			Label:     name,
			Kind:      WorkloadKind,
			Namespace: ns,
			Parent:    ns,
		}
	}
	return nodes[wID]
}

// --- Public API ----------------------------------------------------------

// BuildGraph extracts a deterministic directed graph from policies.
//
// It is PURE: no I/O, no mutation of input slices, always returns new
// slices.  Nodes are deduplicated by ID (first-wins); edges are
// deduplicated by (Source, Target, Direction, Protocol, Port).
//
// Sorting (for determinism):
//   - Nodes are sorted by (Kind, ID).
//   - Edges are sorted by (Source, Target, Direction, Protocol, Port).
//
// Peer classification rules:
//   - FromWorkloads / ToWorkloads entries containing "/" → workload node.
//     Split on first "/"; ID = "ns/name"; NS node auto-created as parent.
//   - Entries with "entity:" prefix → reserved node.  ID = "entity:xxx",
//     Label = "xxx" (prefix stripped).
//   - ToCIDRs entries → cidr node; ID = the CIDR string itself.
//   - ToNamespaces entries → a namespace node on the egress edge target.
//   - Any other string (label format, plain name) → selector node;
//     ID = the raw string.
//
// Edge semantics:
//   - IngressRule: one edge per (source peer × port), direction "ingress",
//     target = the policy's workload node.  Empty Ports → one edge with
//     Port 0 and Protocol "".
//   - EgressRule: one edge per (dest peer × port), direction "egress",
//     source = the policy's workload node.  Empty ToPorts → one edge with
//     Port 0 and Protocol "".
func BuildGraph(pols []policy.Policy) Graph {
	// Phase 1 — collect unique nodes and edges.
	type edgeKey struct {
		src, tgt, dir, proto string
		port                 uint16
	}

	nodes := make(map[string]*Node)
	edges := make(map[edgeKey]*Edge)

	for _, pol := range pols {
		wID := pol.WorkloadID
		if wID == "" {
			continue
		}

		// BuildGraph workload node: must contain "/" (namespace/name).
		// WorkloadID without "/" is treated as an unresolvable selector.
		if !strings.Contains(wID, "/") {
			if _, ok := nodes[wID]; !ok {
				nodes[wID] = &Node{
					ID:    wID,
					Label: wID,
					Kind:  SelectorKind,
				}
			}
			continue
		}

		parts := strings.SplitN(wID, "/", 2)
		wNS := parts[0]
		wName := ""
		if len(parts) > 1 {
			wName = parts[1]
		}
		ensureWorkload(nodes, wNS, wName)

		// --- Ingress rules ------------------------------------------------
		for _, rule := range pol.IngressRules {
			// Build port specs to emit (empty → one edge with Proto "", Port 0).
			ports := rule.Ports
			if len(ports) == 0 {
				ports = []policy.PortSpec{{Protocol: "", Port: 0}}
			}

			// Source peers: FromWorkloads + FromEntities
			sources := make([]string, 0, len(rule.FromWorkloads)+len(rule.FromEntities))
			sources = append(sources, rule.FromWorkloads...)
			sources = append(sources, rule.FromEntities...)
			for _, src := range sources {
				sID, sLabel, sKind := classifyPeer(src)
				// Create the source peer node (idempotent).
				switch sKind {
				case WorkloadKind:
					pw := strings.SplitN(src, "/", 2)
					if len(pw) == 2 {
						ensureWorkload(nodes, pw[0], pw[1])
					}
				case ReservedKind:
					if _, ok := nodes[sID]; !ok {
						nodes[sID] = &Node{ID: sID, Label: sLabel, Kind: ReservedKind}
					}
				case CIDRKind:
					if _, ok := nodes[sID]; !ok {
						nodes[sID] = &Node{ID: sID, Label: sID, Kind: CIDRKind}
					}
				case SelectorKind:
					if _, ok := nodes[sID]; !ok {
						nodes[sID] = &Node{ID: sID, Label: sLabel, Kind: SelectorKind}
					}
				}
				for _, ps := range ports {
					ek := edgeKey{
						src:   sID,
						tgt:   wID,
						dir:   "ingress",
						proto: ps.Protocol,
						port:  ps.Port,
					}
					if _, ok := edges[ek]; !ok {
						edges[ek] = &Edge{
							Source:      ek.src,
							Target:      ek.tgt,
							Direction:   ek.dir,
							Protocol:    ek.proto,
							Port:        ek.port,
							Description: rule.Description,
						}
					}
				}
			}
		}

		// --- Egress rules -------------------------------------------------
		for _, rule := range pol.EgressRules {
			ports := rule.ToPorts
			if len(ports) == 0 {
				ports = []policy.PortSpec{{Protocol: "", Port: 0}}
			}

			// Destination peers: ToWorkloads + ToEntities + ToNamespaces + ToCIDRs
			type dstInfo struct {
				id   string
				kind NodeKind
			}
			var dests []dstInfo

			for _, tw := range rule.ToWorkloads {
				id, _, k := classifyPeer(tw)
				dests = append(dests, dstInfo{id: id, kind: k})
				// ensure workload node exists
				pw := strings.SplitN(tw, "/", 2)
				if k == WorkloadKind && len(pw) == 2 {
					ensureWorkload(nodes, pw[0], pw[1])
				}
			}
			for _, te := range rule.ToEntities {
				id, _, k := classifyPeer(te)
				dests = append(dests, dstInfo{id: id, kind: k})
			}
			for _, tn := range rule.ToNamespaces {
				ensureNs(nodes, tn)
				dests = append(dests, dstInfo{id: tn, kind: NamespaceKind})
			}
			for _, tc := range rule.ToCIDRs {
				id, _, k := classifyPeer(tc)
				dests = append(dests, dstInfo{id: id, kind: k})
			}

			for _, dst := range dests {
				// Create the destination peer node (idempotent).
				switch dst.kind {
				case WorkloadKind:
					pw := strings.SplitN(dst.id, "/", 2)
					if len(pw) == 2 {
						ensureWorkload(nodes, pw[0], pw[1])
					}
				case ReservedKind:
					if _, ok := nodes[dst.id]; !ok {
						nodes[dst.id] = &Node{ID: dst.id, Label: strings.TrimPrefix(dst.id, "entity:"), Kind: ReservedKind}
					}
				case CIDRKind:
					if _, ok := nodes[dst.id]; !ok {
						nodes[dst.id] = &Node{ID: dst.id, Label: dst.id, Kind: CIDRKind}
					}
				case SelectorKind:
					if _, ok := nodes[dst.id]; !ok {
						nodes[dst.id] = &Node{ID: dst.id, Label: dst.id, Kind: SelectorKind}
					}
				case NamespaceKind:
					ensureNs(nodes, dst.id)
				}
				for _, ps := range ports {
					ek := edgeKey{
						src:   wID,
						tgt:   dst.id,
						dir:   "egress",
						proto: ps.Protocol,
						port:  ps.Port,
					}
					if _, ok := edges[ek]; !ok {
						edges[ek] = &Edge{
							Source:      ek.src,
							Target:      ek.tgt,
							Direction:   ek.dir,
							Protocol:    ek.proto,
							Port:        ek.port,
							Description: rule.Description,
						}
					}
				}
			}
		}
	}

	// Phase 2 — convert maps to sorted slices.
	// Nodes: sorted by (Kind, ID).
	sortNodes := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		sortNodes = append(sortNodes, *n)
	}
	sortAllNodes(sortNodes)

	// Edges: sorted by (Source, Target, Direction, Protocol, Port).
	sortEdges := make([]Edge, 0, len(edges))
	for _, e := range edges {
		sortEdges = append(sortEdges, *e)
	}
	sortAllEdges(sortEdges)

	return Graph{
		Nodes: sortNodes,
		Edges: sortEdges,
	}
}

// --- Sorting ---

func nodeLess(a, b Node) int {
	if r := cmp.Compare(string(a.Kind), string(b.Kind)); r != 0 {
		return r
	}
	return cmp.Compare(a.ID, b.ID)
}

func sortAllNodes(nodes []Node) {
	slices.SortFunc(nodes, nodeLess)
}

func edgeLess(a, b Edge) int {
	if r := cmp.Compare(a.Source, b.Source); r != 0 {
		return r
	}
	if r := cmp.Compare(a.Target, b.Target); r != 0 {
		return r
	}
	if r := cmp.Compare(a.Direction, b.Direction); r != 0 {
		return r
	}
	if r := cmp.Compare(a.Protocol, b.Protocol); r != 0 {
		return r
	}
	return cmp.Compare(a.Port, b.Port)
}

func sortAllEdges(edges []Edge) {
	slices.SortFunc(edges, edgeLess)
}
