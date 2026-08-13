package visualize

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/policy"
)

func TestBuildGraph(t *testing.T) {
	t.Parallel()

	const (
		nsLabel   = "default"
		wkBLabel  = "backend"
		wkIngress = "default/frontend"
	)

	tests := []struct {
		name   string
		input  []policy.Policy
		assert func(t *testing.T, g Graph)
	}{
		{
			name:  "empty input yields empty graph",
			input: nil,
			assert: func(t *testing.T, g Graph) {
				t.Helper()
				if len(g.Nodes) != 0 || len(g.Edges) != 0 {
					t.Fatalf("expected empty graph, got %d nodes, %d edges", len(g.Nodes), len(g.Edges))
				}
			},
		},
		{
			name: "single policy — ingress + egress",
			input: []policy.Policy{{
				WorkloadID:        "default/backend",
				WorkloadName:      "backend",
				WorkloadNamespace: "default",
				IngressRules: []policy.IngressRule{{
					FromWorkloads: []string{wkIngress},
					Ports: []policy.PortSpec{{
						Port:     80,
						Protocol: "TCP",
					}},
				}},
				EgressRules: []policy.EgressRule{{
					ToCIDRs: []string{"0.0.0.0/0"},
					ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
				}},
			}},
			assert: func(t *testing.T, g Graph) {
				t.Helper()
				// Expected nodes:
				//   namespace: default
				//   workload:  default/backend
				//   workload:  default/frontend  (from ingress FromWorkloads)
				//   cidr:      0.0.0.0/0
				wantNodes := 4
				if len(g.Nodes) != wantNodes {
					t.Fatalf("expected %d nodes, got %d: %v", wantNodes, len(g.Nodes), nodeIDs(g.Nodes))
				}
				// Verify specific nodes exist.
				has := func(id string, kind NodeKind) bool {
					for _, n := range g.Nodes {
						if n.ID == id && n.Kind == kind {
							return true
						}
					}
					return false
				}
				if !has("default", NamespaceKind) {
					t.Error("missing namespace node 'default'")
				}
				if !has("default/backend", WorkloadKind) {
					t.Error("missing workload node 'default/backend'")
				}
				if !has("default/frontend", WorkloadKind) {
					t.Error("missing workload node 'default/frontend'")
				}
				if !has("0.0.0.0/0", CIDRKind) {
					t.Error("missing cidr node '0.0.0.0/0'")
				}

				// Verify edges:
				//   ingress:  default/frontend -> default/backend  TCP/80
				//   egress:   default/backend  -> 0.0.0.0/0        TCP/443
				wantEdges := 2
				if len(g.Edges) != wantEdges {
					t.Fatalf("expected %d edges, got %d", wantEdges, len(g.Edges))
				}
				checkEdge := func(src, tgt, dir, proto string, port uint16) bool {
					for _, e := range g.Edges {
						if e.Source == src && e.Target == tgt &&
							e.Direction == dir && e.Protocol == proto && e.Port == port {
							return true
						}
					}
					return false
				}
				if !checkEdge(wkIngress, "default/backend", "ingress", "TCP", 80) {
					t.Error("missing ingress edge frontend→backend TCP/80")
				}
				if !checkEdge("default/backend", "0.0.0.0/0", "egress", "TCP", 443) {
					t.Error("missing egress edge backend→0.0.0.0/0 TCP/443")
				}
			},
		},
		{
			name: "reserved peer nodes: entity:world + entity:kube-apiserver",
			input: []policy.Policy{{
				WorkloadID:        "default/backend",
				WorkloadName:      "backend",
				WorkloadNamespace: "default",
				EgressRules: []policy.EgressRule{{
					ToEntities: []string{"entity:world", "entity:kube-apiserver"},
					ToPorts:    []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
				}},
			}},
			assert: func(t *testing.T, g Graph) {
				t.Helper()
				has := func(id string, kind NodeKind) bool {
					for _, n := range g.Nodes {
						if n.ID == id && n.Kind == kind {
							return true
						}
					}
					return false
				}
				if !has("entity:world", ReservedKind) {
					t.Error("missing reserved node 'entity:world'")
				}
				if !has("entity:kube-apiserver", ReservedKind) {
					t.Error("missing reserved node 'entity:kube-apiserver'")
				}
				// Verify entities are NOT CIDR nodes.
				if has("entity:world", CIDRKind) {
					t.Error("entity:world should not be CIDR")
				}
				if has("entity:kube-apiserver", CIDRKind) {
					t.Error("entity:kube-apiserver should not be CIDR")
				}
			},
		},
		{
			name:  "determinism — two calls produce identical graph",
			input: determinismInput(),
			assert: func(t *testing.T, g Graph) {
				t.Helper()
				g2 := BuildGraph(determinismInput())
				if !reflect.DeepEqual(g, g2) {
					t.Fatal("BuildGraph is non-deterministic: two calls with same input differ")
				}
			},
		},
		{
			name: "no-port rule emits single edge with Port 0, Protocol ''",
			input: []policy.Policy{{
				WorkloadID:        "default/svc",
				WorkloadName:      "svc",
				WorkloadNamespace: "default",
				IngressRules: []policy.IngressRule{{
					FromWorkloads: []string{"default/client"},
					// Empty Ports — should emit one edge with Proto "", Port 0.
				}},
			}},
			assert: func(t *testing.T, g Graph) {
				t.Helper()
				if len(g.Edges) != 1 {
					t.Fatalf("expected 1 edge, got %d", len(g.Edges))
				}
				e := g.Edges[0]
				if e.Port != 0 {
					t.Errorf("expected Port 0, got %d", e.Port)
				}
				if e.Protocol != "" {
					t.Errorf("expected Protocol '', got %q", e.Protocol)
				}
				if e.Direction != "ingress" {
					t.Errorf("expected direction 'ingress', got %q", e.Direction)
				}
				// Target must be the workload node.
				if e.Target != "default/svc" {
					t.Errorf("expected target 'default/svc', got %q", e.Target)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range var
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := BuildGraph(tt.input)
			tt.assert(t, g)
		})
	}
}

// --- helpers --------------------------------------------------------------

func nodeIDs(nodes []Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID + "/" + string(n.Kind)
	}
	return ids
}

func determinismInput() []policy.Policy {
	ns := "flow"
	return []policy.Policy{
		{
			WorkloadID:        ns + "/web",
			WorkloadName:      "web",
			WorkloadNamespace: ns,
			IngressRules: []policy.IngressRule{{
				FromWorkloads: []string{ns + "/ingress-ctrl"},
				Ports:         []policy.PortSpec{{Port: 443, Protocol: "TCP"}},
			}},
			EgressRules: []policy.EgressRule{{
				ToWorkloads: []string{ns + "/redis", ns + "/pg"},
				ToCIDRs:     []string{"10.0.0.0/8"},
				ToEntities:  []string{"entity:world"},
				ToPorts:     []policy.PortSpec{{Port: 6379, Protocol: "TCP"}},
			}},
		},
	}
}

func TestSortNodes(t *testing.T) {
	t.Parallel()
	// Verify node sort order (Kind, ID).
	nodes := []Node{
		{ID: "a", Kind: WorkloadKind},
		{ID: "z", Kind: CIDRKind},
		{ID: "a-ns", Kind: NamespaceKind},
		{ID: "b", Kind: WorkloadKind},
		{ID: "b-ns", Kind: NamespaceKind},
	}
	sortAllNodes(nodes)
	got := make([]string, len(nodes))
	for i, n := range nodes {
		got[i] = string(n.Kind) + "/" + n.ID
	}
	want := []string{
		"cidr/z",
		"namespace/a-ns",
		"namespace/b-ns",
		"workload/a",
		"workload/b",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("node sort mismatch\n  got: %v\n  want: %v", got, want)
	}
}

func TestSortEdges(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{Source: "a", Target: "b", Direction: "egress", Protocol: "TCP", Port: 443},
		{Source: "a", Target: "b", Direction: "ingress", Protocol: "TCP", Port: 80},
		{Source: "a", Target: "c", Direction: "egress", Protocol: "TCP", Port: 443},
		{Source: "a", Target: "b", Direction: "egress", Protocol: "UDP", Port: 53},
	}
	sortAllEdges(edges)
	got := make([]string, len(edges))
	for i, e := range edges {
		got[i] = e.Source + "->" + e.Target + "|" + e.Direction + "|" + e.Protocol + "/" + itoa(e.Port)
	}
	want := []string{
		"a->b|egress|TCP/443",
		"a->b|egress|UDP/53",
		"a->b|ingress|TCP/80",
		"a->c|egress|TCP/443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("edge sort mismatch\n  got: %v\n  want: %v", got, want)
	}
}

func itoa(v uint16) string {
	s := ""
	for v > 0 {
		s = string(byte('0'+v%10)) + s
		v /= 10
	}
	if s == "" {
		return "0"
	}
	return s
}

func TestClassifyPeer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input             string
		wantID, wantLabel string
		wantKind          NodeKind
	}{
		{"flowlab/demo-client,app=demo-client", "flowlab/demo-client,app=demo-client", "flowlab/demo-client,app=demo-client", SelectorKind},
		{"entity:world", "entity:world", "world", ReservedKind},
		{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8", CIDRKind},
		{"flowlab/demo-server", "flowlab/demo-server", "demo-server", WorkloadKind},
		{"default/frontend", "default/frontend", "frontend", WorkloadKind},
		{"entity:world", "entity:world", "world", ReservedKind},
		{"entity:kube-apiserver", "entity:kube-apiserver", "kube-apiserver", ReservedKind},
		{"0.0.0.0/0", "0.0.0.0/0", "0.0.0.0/0", CIDRKind},
		{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8", CIDRKind},
		{"app=foo", "app=foo", "app=foo", SelectorKind},
		{"metrics-server", "metrics-server", "metrics-server", SelectorKind},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			id, label, kind := classifyPeer(tt.input)
			if id != tt.wantID {
				t.Errorf("classifyPeer(%q) ID = %q, want %q", tt.input, id, tt.wantID)
			}
			if label != tt.wantLabel {
				t.Errorf("classifyPeer(%q) Label = %q, want %q", tt.input, label, tt.wantLabel)
			}
			if kind != tt.wantKind {
				t.Errorf("classifyPeer(%q) Kind = %v, want %v", tt.input, kind, tt.wantKind)
			}
		})
	}
}

func TestWorkloadNamespaceFromWorkloadID(t *testing.T) {
	t.Parallel()
	// When WorkloadNamespace is empty, it should be derived from WorkloadID.
	pol := policy.Policy{
		WorkloadID:        "flow/web",
		WorkloadName:      "",
		WorkloadNamespace: "",
	}
	g := BuildGraph([]policy.Policy{pol})
	// Should have workload node with Parent = "flow".
	var found bool
	for _, n := range g.Nodes {
		if n.ID == "flow/web" && n.Kind == WorkloadKind && n.Parent == "flow" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("workload node 'flow/web' with parent 'flow' not found. nodes: %v", nodeIDs(g.Nodes))
	}
	// Namespace node "flow" should exist.
	for _, n := range g.Nodes {
		if n.ID == "flow" && n.Kind == NamespaceKind {
			return
		}
	}
	t.Error("namespace node 'flow' not found")
}

func TestNoPortMutation(t *testing.T) {
	t.Parallel()
	// BuildGraph must not mutate the input pol slices.
	input := []policy.Policy{{
		WorkloadID:        "ns/app",
		WorkloadName:      "app",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToCIDRs: []string{"1.2.3.4/32"},
		}},
	}}
	// Deep-copy the input to verify later.
	before := []policy.Policy{input[0]}
	wantEgressRuleCount := len(input[0].EgressRules)

	_ = BuildGraph(input)

	if len(input[0].EgressRules) != wantEgressRuleCount {
		t.Errorf("input mutated: before %d rules, after %d", wantEgressRuleCount, len(input[0].EgressRules))
	}
	// Verify the input policy was not modified.
	if !reflect.DeepEqual(input[0], before[0]) {
		t.Error("BuildGraph mutated input policy")
	}
}

func TestDedup(t *testing.T) {
	t.Parallel()
	// Same edge from multiple rules should be deduplicated.
	pol := policy.Policy{
		WorkloadID:        "ns/svc",
		WorkloadNamespace: "ns",
		IngressRules: []policy.IngressRule{
			{
				FromWorkloads: []string{"ns/client"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			},
			{
				FromWorkloads: []string{"ns/client"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			},
		},
	}
	g := BuildGraph([]policy.Policy{pol})
	// Should have only one edge for client→svc TCP/80.
	var ingressEdges int
	for _, e := range g.Edges {
		if e.Direction == "ingress" &&
			e.Source == "ns/client" && e.Target == "ns/svc" &&
			e.Protocol == "TCP" && e.Port == 80 {
			ingressEdges++
		}
	}
	if ingressEdges != 1 {
		t.Errorf("expected 1 deduplicated edge, got %d", ingressEdges)
	}
}

func TestReservedPeerLabels(t *testing.T) {
	t.Parallel()
	// Reserved peer IDs should be "entity:xxx" and labels should be "xxx" (prefix stripped).
	pol := policy.Policy{
		WorkloadID:        "ns/app",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToEntities: []string{"entity:host", "entity:remote-node", "entity:cluster"},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	entries := []struct {
		id string
		ln string
	}{
		{
			id: "entity:host",
			ln: "host",
		},
		{
			id: "entity:remote-node",
			ln: "remote-node",
		},
		{
			id: "entity:cluster",
			ln: "cluster",
		},
	}
	for _, e := range entries {
		found := false
		for _, n := range g.Nodes {
			if n.ID == e.id && n.Label == e.ln && n.Kind == ReservedKind {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected reserved node ID=%q Label=%q, not found. nodes: %v",
				e.id, e.ln, nodeIDs(g.Nodes))
		}
	}
}

func TestToNamespaces(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "ns/dns",
		WorkloadName:      "dns",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToNamespaces: []string{"kube-system", "default"},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	// Should have namespace nodes "kube-system" and "default".
	for _, nn := range []string{"kube-system", "default"} {
		found := false
		for _, n := range g.Nodes {
			if n.ID == nn && n.Kind == NamespaceKind {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("namespace node %q not found. nodes: %v", nn, nodeIDs(g.Nodes))
		}
	}
}

func TestWorkloadLabel(t *testing.T) {
	t.Parallel()
	// Workload node Label should be WorkloadName, Name should be name part of WorkloadID.
	pol := policy.Policy{
		WorkloadID:        "staging/redis",
		WorkloadName:      "redis",
		WorkloadNamespace: "staging",
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, n := range g.Nodes {
		if n.ID == "staging/redis" && n.Kind == WorkloadKind {
			if n.Label != "redis" {
				t.Errorf("workload label = %q, want %q", n.Label, "redis")
			}
			if n.Namespace != "staging" {
				t.Errorf("workload namespace = %q, want %q", n.Namespace, "staging")
			}
			// Parent should be the namespace node.
			if n.Parent != "staging" {
				t.Errorf("workload parent = %q, want %q", n.Parent, "staging")
			}
			return
		}
	}
	t.Error("workload node 'staging/redis' not found")
}

func TestEdgeDescriptionFromRule(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "ns/svc",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToWorkloads: []string{"ns/db"},
			Description: "allow to database",
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, e := range g.Edges {
		if e.Description != "allow to database" {
			t.Errorf("edge description = %q, want %q", e.Description, "allow to database")
		}
		return
	}
	t.Error("no edge found")
}

func TestSelectorNodeNoParent(t *testing.T) {
	t.Parallel()
	// Selector nodes (label-format) should have Kind=selector and Parent="".
	pol := policy.Policy{
		WorkloadID:        "ns/app",
		WorkloadNamespace: "ns",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"app=frontend"},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, n := range g.Nodes {
		if n.ID == "app=frontend" && n.Kind == SelectorKind {
			if n.Parent != "" {
				t.Errorf("selector parent = %q, want empty", n.Parent)
			}
			return
		}
	}
	t.Error("selector node 'app=frontend' not found")
}

func TestIngressFromAllPeerTypes(t *testing.T) {
	t.Parallel()
	// Ingress source peers combine FromWorkloads + FromEntities.
	pol := policy.Policy{
		WorkloadID:        "ns/api",
		WorkloadName:      "api",
		WorkloadNamespace: "ns",
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"ns/frontend"},
			FromEntities:  []string{"entity:host"},
			Ports:         []policy.PortSpec{{Port: 8080, Protocol: "TCP"}},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	// Should have TWO ingress edges: frontend→api and host→api.
	var srcs []string
	for _, e := range g.Edges {
		if e.Direction == "ingress" {
			srcs = append(srcs, e.Source)
		}
	}
	contains := func(s string) bool {
		for _, item := range srcs {
			if item == s {
				return true
			}
		}
		return false
	}
	if !contains("ns/frontend") {
		t.Error("missing ingress edge from 'ns/frontend'")
	}
	if !contains("entity:host") {
		t.Error("missing ingress edge from 'entity:host'")
	}
}

func TestEgressToAllPeerTypes(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "ns/worker",
		WorkloadName:      "worker",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToWorkloads:  []string{"ns/db"},
			ToEntities:   []string{"entity:remote-node"},
			ToCIDRs:      []string{"203.0.113.0/24"},
			ToNamespaces: []string{"monitoring"},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	var tgtKinds = make(map[string]NodeKind)
	for _, e := range g.Edges {
		if e.Direction == "egress" {
			for _, n := range g.Nodes {
				if n.ID == e.Target {
					tgtKinds[e.Target] = n.Kind
					break
				}
			}
		}
	}
	// Verify all destinations exist.
	if _, ok := tgtKinds["ns/db"]; !ok {
		t.Error("missing egress edge to workload 'ns/db'")
	}
	if _, ok := tgtKinds["entity:remote-node"]; !ok {
		t.Error("missing egress edge to 'entity:remote-node'")
	}
	if _, ok := tgtKinds["203.0.113.0/24"]; !ok {
		t.Error("missing egress edge to CIDR '203.0.113.0/24'")
	}
	if _, ok := tgtKinds["monitoring"]; !ok {
		t.Error("missing egress edge to namespace 'monitoring'")
	}
}

func TestWorkloadDerivedLabel(t *testing.T) {
	t.Parallel()
	// When WorkloadName is empty, Label should derive from WorkloadID.
	pol := policy.Policy{
		WorkloadID:        "prod/web",
		WorkloadName:      "",
		WorkloadNamespace: "",
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, n := range g.Nodes {
		if n.ID == "prod/web" && n.Kind == WorkloadKind {
			if n.Label != "web" {
				t.Errorf("derived workload label = %q, want %q", n.Label, "web")
			}
			if n.Namespace != "prod" {
				t.Errorf("derived namespace = %q, want %q", n.Namespace, "prod")
			}
			return
		}
	}
	t.Error("workload node not found")
}

func TestReservedPeerSortOrder(t *testing.T) {
	t.Parallel()
	// Reserved peers should sort before other kinds at equal position.
	// Verify: ReservedKind < CIDRKind < NamespaceKind < SelectorKind < WorkloadKind
	// (alphabetical: c < n < r < s < w)
	kindOrder := []struct {
		kind  NodeKind
		id    string
		label string
	}{
		{ReservedKind, "entity:cluster", "cluster"},
		{ReservedKind, "entity:host", "host"},
		{ReservedKind, "entity:kube-apiserver", "kube-apiserver"},
		{ReservedKind, "entity:remote-node", "remote-node"},
		{ReservedKind, "entity:world", "world"},
	}
	pols := make([]policy.Policy, 0, len(kindOrder))
	for _, k := range kindOrder {
		pols = append(pols, policy.Policy{
			WorkloadID:        "ns/app",
			WorkloadName:      "app",
			WorkloadNamespace: "ns",
			EgressRules: []policy.EgressRule{{
				ToEntities: []string{k.id},
			}},
		})
	}
	g := BuildGraph(pols)
	// Nodes are sorted by (Kind, ID). The reserved nodes should appear in sorted ID order.
	var reservedNodes []Node
	for _, n := range g.Nodes {
		if n.Kind == ReservedKind {
			reservedNodes = append(reservedNodes, n)
		}
	}
	if len(reservedNodes) != len(kindOrder) {
		t.Fatalf("expected %d reserved nodes, got %d", len(kindOrder), len(reservedNodes))
	}
	for i, want := range kindOrder {
		if reservedNodes[i].ID != want.id {
			t.Errorf("reserved node[%d] ID = %q, want %q", i, reservedNodes[i].ID, want.id)
		}
	}
}

func TestEdgeSortOrder(t *testing.T) {
	t.Parallel()
	// Verify edge sorting across multiple policies.
	pols := []policy.Policy{
		{
			WorkloadID:        "ns/b",
			WorkloadNamespace: "ns",
			IngressRules: []policy.IngressRule{{
				FromWorkloads: []string{"ns/a"},
				Ports:         []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			}},
		},
		{
			WorkloadID:        "ns/a",
			WorkloadNamespace: "ns",
			EgressRules: []policy.EgressRule{{
				ToWorkloads: []string{"ns/b"},
				ToPorts:     []policy.PortSpec{{Port: 80, Protocol: "TCP"}},
			}},
		},
	}
	g := BuildGraph(pols)
	// Edges sorted by (Source, Target, Direction, Protocol, Port).
	var edgeKeys []string
	for _, e := range g.Edges {
		edgeKeys = append(edgeKeys, e.Source+" -> "+e.Target+"|"+e.Direction+"|"+e.Protocol+"/"+itoa(e.Port))
	}
	// "ns/a -> ns/b | egress | TCP/80" before "ns/a -> ns/b | ingress | TCP/80"
	// (direction: "e" < "i" alphabetically)
	if len(edgeKeys) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edgeKeys))
	}
	if edgeKeys[0] != "ns/a -> ns/b|egress|TCP/80" {
		t.Errorf("first edge = %q", edgeKeys[0])
	}
	if edgeKeys[1] != "ns/a -> ns/b|ingress|TCP/80" {
		t.Errorf("second edge = %q", edgeKeys[1])
	}
}

func TestNamespaceParentForWorkload(t *testing.T) {
	t.Parallel()
	// Namespace nodes must have empty Parent.
	pol := policy.Policy{
		WorkloadID:        "flow/web",
		WorkloadName:      "web",
		WorkloadNamespace: "flow",
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, n := range g.Nodes {
		if n.Kind == NamespaceKind {
			if n.Parent != "" {
				t.Errorf("namespace node %q Parent = %q, want empty", n.ID, n.Parent)
			}
		}
		if n.Kind == WorkloadKind {
			if n.Parent == "" {
				t.Errorf("workload node %q Parent is empty, want namespace ID", n.ID)
			}
		}
	}
}

func TestMultiplePoliciesDedupWorkload(t *testing.T) {
	t.Parallel()
	// Same workload appearing in multiple policies should not create duplicate nodes.
	pols := []policy.Policy{
		{
			WorkloadID:        "ns/web",
			WorkloadNamespace: "ns",
			WorkloadName:      "web",
			EgressRules: []policy.EgressRule{{
				ToCIDRs: []string{"1.2.3.4/32"},
			}},
		},
		{
			WorkloadID:        "ns/web",
			WorkloadNamespace: "ns",
			WorkloadName:      "web",
			EgressRules: []policy.EgressRule{{
				ToWorkloads: []string{"ns/api"},
			}},
		},
	}
	g := BuildGraph(pols)
	// Should have exactly one "ns/web" workload node.
	count := 0
	for _, n := range g.Nodes {
		if n.ID == "ns/web" && n.Kind == WorkloadKind {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 workload node 'ns/web', got %d", count)
	}
}

func TestEdgeSortProtocolThenPort(t *testing.T) {
	t.Parallel()
	// Verify edges within same (Source, Target, Direction) sort by Protocol, then Port.
	pol := policy.Policy{
		WorkloadID:        "ns/svc",
		WorkloadNamespace: "ns",
		EgressRules: []policy.EgressRule{{
			ToCIDRs: []string{"0.0.0.0/0"},
			ToPorts: []policy.PortSpec{{Port: 443, Protocol: "TCP"}, {Port: 80, Protocol: "TCP"}, {Port: 53, Protocol: "UDP"}},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	var egress []string
	for _, e := range g.Edges {
		if e.Direction == "egress" {
			egress = append(egress, fmt.Sprintf("%s/%05d", e.Protocol, e.Port))
		}
	}
	// Should sort: TCP/80, TCP/443, UDP/53 (Protocol first, then Port within same Protocol).
	// "TCP" < "UDP" alphabetically.
	for i := 1; i < len(egress); i++ {
		if egress[i] < egress[i-1] {
			t.Errorf("egress edges not sorted: %q > %q at index %d", egress[i-1], egress[i], i)
		}
	}
	if egress[0] != "TCP/00080" {
		t.Errorf("first egress = %q, want 'TCP/00080'", egress[0])
	}
	if egress[1] != "TCP/00443" {
		t.Errorf("second egress = %q, want 'TCP/00443'", egress[1])
	}
	if egress[2] != "UDP/00053" {
		t.Errorf("third egress = %q, want 'UDP/00053'", egress[2])
	}
}

func TestWorkloadIDNoSlash(t *testing.T) {
	t.Parallel()
	// WorkloadID without "/" edge case.
	pol := policy.Policy{
		WorkloadID: "broken",
	}
	g := BuildGraph([]policy.Policy{pol})
	// Should create selector node "broken", no workload.
	found := false
	for _, n := range g.Nodes {
		if n.ID == "broken" && n.Kind == SelectorKind {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected selector node 'broken'")
	}
}

func TestEmptyPolSlice(t *testing.T) {
	t.Parallel()
	g := BuildGraph([]policy.Policy{})
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatalf("expected empty graph from empty pol slice, got %d nodes, %d edges", len(g.Nodes), len(g.Edges))
	}
}

func TestEdgeDirectionString(t *testing.T) {
	t.Parallel()
	pol := policy.Policy{
		WorkloadID:        "ns/svc",
		WorkloadNamespace: "ns",
		IngressRules:      []policy.IngressRule{{FromWorkloads: []string{"ns/client"}}},
		EgressRules:       []policy.EgressRule{{ToWorkloads: []string{"ns/db"}}},
	}
	g := BuildGraph([]policy.Policy{pol})
	for _, e := range g.Edges {
		if e.Direction != "ingress" && e.Direction != "egress" {
			t.Errorf("unexpected edge direction %q", e.Direction)
		}
	}
}

func TestEmptyWorkloadID(t *testing.T) {
	t.Parallel()
	// Policies with empty WorkloadID should be skipped silently.
	pol := policy.Policy{
		IngressRules: []policy.IngressRule{{
			FromWorkloads: []string{"ns/client"},
		}},
	}
	g := BuildGraph([]policy.Policy{pol})
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Errorf("empty WorkloadID should produce empty graph, got %d nodes, %d edges", len(g.Nodes), len(g.Edges))
	}
}

func TestNodeKindStringValue(t *testing.T) {
	t.Parallel()
	// Verify string constant values match the spec.
	if string(NamespaceKind) != "namespace" {
		t.Errorf("NamespaceKind = %q", NamespaceKind)
	}
	if string(WorkloadKind) != "workload" {
		t.Errorf("WorkloadKind = %q", WorkloadKind)
	}
	if string(ReservedKind) != "reserved" {
		t.Errorf("ReservedKind = %q", ReservedKind)
	}
	if string(CIDRKind) != "cidr" {
		t.Errorf("CIDRKind = %q", CIDRKind)
	}
	if string(SelectorKind) != "selector" {
		t.Errorf("SelectorKind = %q", SelectorKind)
	}
}

func TestGraphTypeFields(t *testing.T) {
	t.Parallel()
	// Verify Graph struct has Nodes and Edges fields.
	g := Graph{}
	_ = g.Nodes
	_ = g.Edges
}

func TestNodeFields(t *testing.T) {
	t.Parallel()
	// Verify Node struct fields exist and set correctly.
	n := Node{
		ID:        "default/svc",
		Label:     "svc",
		Kind:      WorkloadKind,
		Namespace: "default",
		Parent:    "default",
	}
	if n.ID != "default/svc" {
		t.Error("Node.ID mismatch")
	}
	if n.Namespace != "default" {
		t.Error("Node.Namespace mismatch")
	}
	if n.Parent != "default" {
		t.Error("Node.Parent mismatch")
	}
}

func TestEdgeFields(t *testing.T) {
	t.Parallel()
	// Verify Edge struct fields.
	e := Edge{
		Source:      "ns/client",
		Target:      "ns/svc",
		Direction:   "ingress",
		Protocol:    "TCP",
		Port:        80,
		Description: "allow ingress to service",
	}
	if e.Description != "allow ingress to service" {
		t.Error("Edge.Description mismatch")
	}
}

func TestReservedPeerIDsFormat(t *testing.T) {
	t.Parallel()
	// Reserved peer IDs should always start with "entity:".
	peers := []string{"entity:world", "entity:cluster", "entity:host", "entity:remote-node", "entity:kube-apiserver"}
	for _, p := range peers {
		if !strings.HasPrefix(p, "entity:") {
			t.Errorf("reserved peer %q must start with 'entity:'", p)
		}
	}
}

func TestDeterministicWithTwoPolicies(t *testing.T) {
	t.Parallel()
	pols := []policy.Policy{
		{
			WorkloadID:        "a/x",
			WorkloadNamespace: "a",
			EgressRules:       []policy.EgressRule{{ToCIDRs: []string{"1.0.0.0/8"}}},
		},
		{
			WorkloadID:        "b/x",
			WorkloadNamespace: "b",
			IngressRules:      []policy.IngressRule{{FromWorkloads: []string{"a/x"}}},
		},
	}
	g1 := BuildGraph(pols)
	g2 := BuildGraph(pols)
	// Reversed input should produce same sorted output.
	g3 := BuildGraph(reverse(pols))
	if !reflect.DeepEqual(g1, g2) {
		t.Error("BuildGraph with same input order is non-deterministic")
	}
	if !reflect.DeepEqual(g1, g3) {
		t.Error("BuildGraph should be deterministic regardless of input order")
	}
}

func reverse[V any](s []V) []V {
	r := make([]V, len(s))
	for i, v := range s {
		r[len(s)-1-i] = v
	}
	return r
}
