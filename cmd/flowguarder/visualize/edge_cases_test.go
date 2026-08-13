package visualize

import (
	"reflect"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/policy"
)

// --- helper: node existence ---

func hasNode(g Graph, id string, kind NodeKind) bool {
	for _, n := range g.Nodes {
		if n.ID == id && n.Kind == kind {
			return true
		}
	}
	return false
}

// --- test 1: cross-namespace edges ---

func TestBuildGraphCrossNamespace(t *testing.T) {
	t.Parallel()
	// Policy workload in "prod" namespace, ingress peer from "staging".
	pol := policy.Policy{
		WorkloadID:        "prod/api",
		WorkloadName:      "api",
		WorkloadNamespace: "prod",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"staging/frontend"},
			Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
		}},
		EgressRules: []policy.EgressRule{{
			ToWorkloads: []string{"staging/cache"},
			ToPorts:     []policy.PortSpec{{Port: 6379, Protocol: "TCP"}},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})

	// Namespace compound nodes must both exist.
	if !hasNode(g, "prod", NamespaceKind) {
		t.Error("missing namespace node 'prod'")
	}
	if !hasNode(g, "staging", NamespaceKind) {
		t.Error("missing namespace node 'staging'")
	}

	// Workload nodes: policy workload + ingress peer + egress target.
	for _, id := range []string{"prod/api", "staging/frontend", "staging/cache"} {
		if !hasNode(g, id, WorkloadKind) {
			t.Errorf("missing workload node %q", id)
		}
	}

	// Cross-namespace ingress edge: staging/frontend → prod/api.
	ingressSrc := "staging/frontend"
	ingressTgt := "prod/api"
	foundIngress := false
	for _, e := range g.Edges {
		if e.Source == ingressSrc && e.Target == ingressTgt &&
			e.Direction == "ingress" && e.Protocol == "TCP" && e.Port == 8080 {
			foundIngress = true
			break
		}
	}
	if !foundIngress {
		t.Errorf("missing cross-namespace ingress edge %s → %s", ingressSrc, ingressTgt)
	}

	// Cross-namespace egress edge: prod/api → staging/cache.
	egressSrc := "prod/api"
	egressTgt := "staging/cache"
	foundEgress := false
	for _, e := range g.Edges {
		if e.Source == egressSrc && e.Target == egressTgt &&
			e.Direction == "egress" && e.Protocol == "TCP" && e.Port == 6379 {
			foundEgress = true
			break
		}
	}
	if !foundEgress {
		t.Errorf("missing cross-namespace egress edge %s → %s", egressSrc, egressTgt)
	}

	// Staging namespace node Parent must be empty.
	for _, n := range g.Nodes {
		if n.ID == "staging" && n.Kind == NamespaceKind {
			if n.Parent != "" {
				t.Errorf("namespace node 'staging' Parent = %q, want empty", n.Parent)
			}
			break
		}
	}
}

// --- test 2: workloads with no labels ---

func TestBuildGraphNoLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      []policy.Policy
		wantWlID   string
		wantLabel  string
		wantKind   NodeKind
		wantParent string
		wantNsNode string // namespace node ID expected ("" = skip)
	}{
		{
			name:       "derived from WorkloadID, WorkloadNamespace empty",
			input:      []policy.Policy{{WorkloadID: "lonely/ghost", WorkloadName: "", WorkloadNamespace: ""}},
			wantWlID:   "lonely/ghost",
			wantLabel:  "ghost",
			wantKind:   WorkloadKind,
			wantParent: "lonely",
			wantNsNode: "lonely",
		},
		{
			name:       "WorkloadName set, WorkloadNamespace empty",
			input:      []policy.Policy{{WorkloadID: "ns/app", WorkloadName: "app", WorkloadNamespace: ""}},
			wantWlID:   "ns/app",
			wantLabel:  "app",
			wantKind:   WorkloadKind,
			wantParent: "ns",
			wantNsNode: "ns",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := BuildGraph(tt.input)

			// Find workload node.
			var found bool
			for _, n := range g.Nodes {
				if n.ID == tt.wantWlID && n.Kind == tt.wantKind {
					if n.Label != tt.wantLabel {
						t.Errorf("workload node %s: Label = %q, want %q", tt.wantWlID, n.Label, tt.wantLabel)
					}
					if n.Parent != tt.wantParent {
						t.Errorf("workload node %s: Parent = %q, want %q", tt.wantWlID, n.Parent, tt.wantParent)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("workload node %s (kind=%s) not found in: %v", tt.wantWlID, tt.wantKind, nodeIDs(g.Nodes))
			}

			// Namespace parent node must exist.
			if tt.wantNsNode != "" {
				if !hasNode(g, tt.wantNsNode, NamespaceKind) {
					t.Errorf("expected namespace node %q not found", tt.wantNsNode)
				}
			}
		})
	}
}

// --- test 3: multiple ports per rule ---

func TestBuildGraphMultiPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      policy.Policy
		wantEdgeCnt int
		// Each (source, target, direction, proto, port).
		wantEdges []struct {
			src, tgt, dir, proto string
			port                 uint16
		}
	}{
		{
			name: "ingress multi-port: TCP/80 + TCP/443",
			policy: policy.Policy{
				WorkloadID:        "web/app",
				WorkloadName:      "app",
				WorkloadNamespace: "web",
				IngressRules: []policy.IngressRule{{
					FromWorkloads: []string{"web/client"},
					Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}, {Port: 443, Protocol: "TCP"}},
				}},
			},
			wantEdgeCnt: 2,
			wantEdges: []struct {
				src, tgt, dir, proto string
				port                 uint16
			}{
				{"web/client", "web/app", "ingress", "TCP", 80},
				{"web/client", "web/app", "ingress", "TCP", 443},
			},
		},
		{
			name: "egress multi-port: TCP/80 + UDP/53 + TCP/443",
			policy: policy.Policy{
				WorkloadID:        "worker/proc",
				WorkloadName:      "proc",
				WorkloadNamespace: "worker",
				EgressRules: []policy.EgressRule{{
					ToWorkloads: []string{"worker/db"},
					ToPorts:     []policy.PortSpec{{Port: 80, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}, {Port: 443, Protocol: "TCP"}},
				}},
			},
			wantEdgeCnt: 3,
			wantEdges: []struct {
				src, tgt, dir, proto string
				port                 uint16
			}{
				{"worker/proc", "worker/db", "egress", "TCP", 80},
				{"worker/proc", "worker/db", "egress", "TCP", 443},
				{"worker/proc", "worker/db", "egress", "UDP", 53},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := BuildGraph([]policy.Policy{tt.policy})

			if len(g.Edges) != tt.wantEdgeCnt {
				t.Fatalf("expected %d edges, got %d: %v", tt.wantEdgeCnt, len(g.Edges),
					func() []string {
						var s []string
						for _, e := range g.Edges {
							s = append(s, e.Source+"→"+e.Target+"|"+e.Direction+"|"+e.Protocol+"/"+itoa(e.Port))
						}
						return s
					}())
			}

			for _, want := range tt.wantEdges {
				found := false
				for _, e := range g.Edges {
					if e.Source == want.src && e.Target == want.tgt &&
						e.Direction == want.dir && e.Protocol == want.proto && e.Port == want.port {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing edge %s → %s [%s %s/%d]", want.src, want.tgt, want.dir, want.proto, want.port)
				}
			}
		})
	}
}

// --- test 4: ingress-only and egress-only policies ---

func TestBuildGraphIngressOnly(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "app/svc",
		WorkloadName:      "svc",
		WorkloadNamespace: "app",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"app/client"},
			Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
		}},
		// No EgressRules.
	}
	g := BuildGraph([]policy.Policy{pol})

	// There should be NO egress edges at all.
	for _, e := range g.Edges {
		if e.Direction == "egress" {
			t.Errorf("unexpected egress edge: %s → %s", e.Source, e.Target)
		}
	}

	// Must have exactly one ingress edge.
	var ingressCount int
	for _, e := range g.Edges {
		if e.Direction == "ingress" {
			ingressCount++
		}
	}
	if ingressCount != 1 {
		t.Errorf("expected 1 ingress edge, got %d", ingressCount)
	}
}

func TestBuildGraphEgressOnly(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "app/worker",
		WorkloadName:      "worker",
		WorkloadNamespace: "app",
		EgressRules: []policy.EgressRule{{
			ToWorkloads: []string{"app/db"},
			ToPorts:     []policy.PortSpec{{Port: 5432, Protocol: "TCP"}},
		}},
		// No IngressRules.
	}
	g := BuildGraph([]policy.Policy{pol})

	// There should be NO ingress edges at all.
	for _, e := range g.Edges {
		if e.Direction == "ingress" {
			t.Errorf("unexpected ingress edge: %s → %s", e.Source, e.Target)
		}
	}

	// Must have exactly one egress edge.
	var egressCount int
	for _, e := range g.Edges {
		if e.Direction == "egress" {
			egressCount++
		}
	}
	if egressCount != 1 {
		t.Errorf("expected 1 egress edge, got %d", egressCount)
	}
}

// --- test 5: edge-integrity (all edge endpoints exist in Nodes) ---

func TestBuildGraphEdgeIntegrity(t *testing.T) {
	t.Parallel()

	// A complex policy exercise multiple peer types and directions.
	input := []policy.Policy{
		{
			WorkloadID:        "a/x",
			WorkloadName:      "x",
			WorkloadNamespace: "a",
			IngressRules: []policy.IngressRule{{
				FromWorkloads: []string{"b/y", "app=frontend"},
				FromEntities:  []string{"entity:host"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			}},
			EgressRules: []policy.EgressRule{{
				ToWorkloads:  []string{"b/z"},
				ToCIDRs:      []string{"0.0.0.0/0"},
				ToEntities:   []string{"entity:world"},
				ToNamespaces: []string{"monitoring"},
				ToPorts:      []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			}},
		},
	}
	g := BuildGraph(input)

	// Build lookup set of all node IDs.
	nodeSet := make(map[string]struct{}, len(g.Nodes))
	for _, n := range g.Nodes {
		nodeSet[n.ID] = struct{}{}
	}

	missing := make(map[string]int)
	for _, e := range g.Edges {
		if _, ok := nodeSet[e.Source]; !ok {
			missing[e.Source]++
		}
		if _, ok := nodeSet[e.Target]; !ok {
			missing[e.Target]++
		}
	}

	if len(missing) > 0 {
		var msg string
		for id, cnt := range missing {
			msg += "\n  " + id + " referenced " + itoa(uint16(cnt)) + " time(s)"
		}
		t.Errorf("edge-integrity failure — edge endpoints not in Nodes:%s\n  nodes: %v",
			msg, nodeIDs(g.Nodes))
	}
}

// --- combined edge-integrity test with multiple policies ---

func TestBuildGraphMultiPolicyEdgeIntegrity(t *testing.T) {
	t.Parallel()

	input := []policy.Policy{
		{
			WorkloadID:        "ns1/svc1",
			WorkloadNamespace: "ns1",
			IngressRules: []policy.IngressRule{{
				FromWorkloads: []string{"ns2/peer1", "ns2/peer2"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}, {Port: 443, Protocol: "TCP"}},
			}},
		},
		{
			WorkloadID:        "ns2/svc2",
			WorkloadNamespace: "ns2",
			EgressRules: []policy.EgressRule{{
				ToWorkloads: []string{"ns1/svc1", "ns3/svc3"},
				ToPorts:     []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
			}},
		},
	}
	g := BuildGraph(input)

	nodeSet := make(map[string]struct{})
	for _, n := range g.Nodes {
		nodeSet[n.ID] = struct{}{}
	}

	// Both "ns3/svc3" and the "ns3" namespace node should be created
	// even though no explicit policy owns ns3, because ns2 → ns3 is an egress target.
	for id := range nodeSet {
		if id == "ns3/svc3" {
			// Should exist — egress target from ns2/svc2.
			break
		}
	}

	// Check edge integrity.
	for _, e := range g.Edges {
		if _, ok := nodeSet[e.Source]; !ok {
			t.Errorf("edge source %q not in Nodes", e.Source)
		}
		if _, ok := nodeSet[e.Target]; !ok {
			t.Errorf("edge target %q not in Nodes", e.Target)
		}
	}

	// Cross-namespace egress ns1/svc1 (node from ns2 peer) should exist.
	if !hasNode(g, "ns1/svc1", WorkloadKind) {
		t.Error("missing workload 'ns1/svc1' — should be created as egress target from ns2/svc2")
	}
	// "ns3/svc3" should exist as egress target.
	if !hasNode(g, "ns3/svc3", WorkloadKind) {
		t.Error("missing workload 'ns3/svc3' — should be created as egress target from ns2/svc2")
	}
}

// --- edge-integrity via reflection: verify all Edge fields exist ---

func TestBuildGraphEdgeFieldsIntegrity(t *testing.T) {
	t.Parallel()
	g := BuildGraph([]policy.Policy{{
		WorkloadID: "ns/svc",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"ns/peer"},
			Description:   "test rule",
		}},
	}})

	if len(g.Edges) == 0 {
		t.Fatal("expected at least 1 edge")
	}
	e := g.Edges[0]

	// Verify Edge struct fields are populated.
	if e.Source == "" {
		t.Error("edge Source is empty")
	}
	if e.Target == "" {
		t.Error("edge Target is empty")
	}
	if e.Direction != "ingress" && e.Direction != "egress" {
		t.Errorf("edge Direction = %q, expected 'ingress' or 'egress'", e.Direction)
	}
	if e.Description != "test rule" {
		t.Errorf("edge Description = %q, want %q", e.Description, "test rule")
	}

	// Verify edge endpoints exist in Nodes.
	nodeIDs := make(map[string]struct{})
	for _, n := range g.Nodes {
		nodeIDs[n.ID] = struct{}{}
	}
	if _, ok := nodeIDs[e.Source]; !ok {
		t.Errorf("edge source node %q not found", e.Source)
	}
	if _, ok := nodeIDs[e.Target]; !ok {
		t.Errorf("edge target node %q not found", e.Target)
	}
}

// --- additional: multi-port edge-integrity ---

func TestBuildGraphMultiPortEdgeIntegrity(t *testing.T) {
	t.Parallel()
	g := BuildGraph([]policy.Policy{{
		WorkloadID: "ns/svc",
		EgressRules: []policy.EgressRule{{
			ToWorkloads: []string{"ns/db", "ns/redis"},
			ToPorts: []policy.PortSpec{
				{Port: 80, Protocol: "TCP"},
				{Port: 443, Protocol: "TCP"},
				{Port: 53, Protocol: "UDP"},
			},
		}},
	}})

	nodeSet := make(map[string]struct{})
	for _, n := range g.Nodes {
		nodeSet[n.ID] = struct{}{}
	}

	for _, e := range g.Edges {
		if _, ok := nodeSet[e.Source]; !ok {
			t.Errorf("edge source %q not in Nodes", e.Source)
		}
		if _, ok := nodeSet[e.Target]; !ok {
			t.Errorf("edge target %q not in Nodes", e.Target)
		}
	}
}

// --- verify no mutation of input edges/slice via deep copy ---

func TestBuildGraphNoInputMutation(t *testing.T) {
	t.Parallel()
	input := []policy.Policy{{
		WorkloadID:        "mut/ns",
		WorkloadName:      "ns",
		WorkloadNamespace: "mut",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"ns/client"},
			Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
		}},
	}}

	before := reflect.ValueOf(input[0]).Interface()
	_ = BuildGraph(input)

	after := reflect.ValueOf(input[0]).Interface()
	if !reflect.DeepEqual(before, after) {
		t.Error("BuildGraph mutated input policy")
	}
}
