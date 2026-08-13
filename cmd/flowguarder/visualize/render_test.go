package visualize

import (
	"bytes"
	"strings"
	"testing"
)

// fixtureGraph returns a small, realistic Graph for tests.
func fixtureGraph() Graph {
	return Graph{
		Nodes: []Node{
			{ID: "default", Label: "default", Kind: NamespaceKind},
			{ID: "default/nginx", Label: "nginx", Kind: WorkloadKind, Namespace: "default", Parent: "default"},
			{ID: "default/redis", Label: "redis", Kind: WorkloadKind, Namespace: "default", Parent: "default"},
			{ID: "entity:world", Label: "world", Kind: ReservedKind},
		},
		Edges: []Edge{
			{Source: "entity:world", Target: "default/nginx", Direction: "ingress", Protocol: "TCP", Port: 80, Description: "Allow HTTP"},
			{Source: "default/nginx", Target: "default/redis", Direction: "egress", Protocol: "TCP", Port: 6379, Description: "Redis egress"},
		},
	}
}

func TestRenderHTMLStructure(t *testing.T) {
	t.Parallel()
	t.Run("contains required HTML structure", func(t *testing.T) {
		t.Parallel()
		g := fixtureGraph()
		var out bytes.Buffer
		if err := RenderHTML(g, &out); err != nil {
			t.Fatalf("RenderHTML: %v", err)
		}
		h := out.String()
		checks := []string{
			"<!DOCTYPE html>",
			"<html",
			`id="cy"`,
			`id="search-input"`,
			`id="filter-ns"`,
			`<select`,
			`id="filter-proto"`,
			`id="filter-port"`,
			`<input`,
			`id="export-png"`,
			`id="export-jpg"`,
		}
		for _, c := range checks {
			if !strings.Contains(h, c) {
				t.Errorf("output missing %q", c)
			}
		}
	})
	t.Run("export buttons text", func(t *testing.T) {
		t.Parallel()
		g := fixtureGraph()
		var out bytes.Buffer
		if err := RenderHTML(g, &out); err != nil {
			t.Fatalf("RenderHTML: %v", err)
		}
		h := out.String()
		if !strings.Contains(h, "PNG") {
			t.Error("output missing PNG export button text")
		}
		if !strings.Contains(h, "JPG") {
			t.Error("output missing JPG export button text")
		}
	})
}

func TestRenderHTMLNoExternalSources(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()
	var out bytes.Buffer
	if err := RenderHTML(g, &out); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	h := out.String()
	external := []string{
		`src="http://`,
		`src="https://`,
		`href="http://`,
		`href="https://`,
	}
	for _, e := range external {
		if strings.Contains(h, e) {
			t.Errorf("output contains external source reference: %s", e)
		}
	}
}

func TestRenderHTMLDeterministic(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()
	var a, b bytes.Buffer
	if err := RenderHTML(g, &a); err != nil {
		t.Fatalf("first render: %v", err)
	}
	if err := RenderHTML(g, &b); err != nil {
		t.Fatalf("second render: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two renders of the same graph produced different output")
	}
}

func TestRenderHTMLEmptyGraph(t *testing.T) {
	t.Parallel()
	empty := Graph{}
	var out bytes.Buffer
	if err := RenderHTML(empty, &out); err != nil {
		t.Fatalf("RenderHTML(empty) error: %v", err)
	}
	h := out.String()
	if !strings.Contains(h, "<!DOCTYPE html>") {
		t.Error("empty graph output missing DOCTYPE")
	}
	if !strings.Contains(h, "html") {
		t.Error("empty graph output missing html tag")
	}
}

func TestRenderHTMLSize(t *testing.T) {
	t.Parallel()
	// 5 namespaces * 3 workloads each to have meaningful data
	g := Graph{}
	namespaces := []string{"default", "kube-system", "production", "staging", "monitoring"}
	for _, ns := range namespaces {
		g.Nodes = append(g.Nodes, Node{ID: ns, Label: ns, Kind: NamespaceKind})
		for i := 0; i < 3; i++ {
			wid := ns + "/workload-" + strings.Repeat("a", i)
			g.Nodes = append(g.Nodes, Node{ID: wid, Label: "workload-" + strings.Repeat("a", i), Kind: WorkloadKind, Namespace: ns, Parent: ns})
			g.Edges = append(g.Edges, Edge{Source: wid, Target: "entity:world", Direction: "egress", Protocol: "TCP", Port: uint16(443 + i)})
		}
	}

	var out bytes.Buffer
	if err := RenderHTML(g, &out); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if len(out.Bytes()) <= 100*1024 {
		t.Errorf("output size %d bytes, expected > 100KB", len(out.Bytes()))
	}
}

func TestRenderHTMLDataShape(t *testing.T) {
	t.Parallel()
	// The graph data must be a {"nodes":[],"edges":[]} object assigned
	// to a var in an inline script — not a bare nested-array concat.
	g := fixtureGraph()
	var out bytes.Buffer
	if err := RenderHTML(g, &out); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	h := out.String()
	// Must contain the var assignment wrapper around the graph JSON.
	if !strings.Contains(h, "var GRAPH_DATA = {\"nodes\":[") {
		t.Error("output missing var GRAPH_DATA = {\"nodes\":[")
	}
	if !strings.Contains(h, "],\"edges\":[") {
		t.Error("output missing ],\"edges\":[ in graph data")
	}
	// The embedded node JSON must not be a bare top-level array concat
	// (i.e. no [[...],[...]] pattern).
	if strings.Contains(h, "[[\"nodes\"") || strings.Contains(h, "[[\"group\"") {
		t.Error("output contains a nested array [[...],[...]] — should be {\"nodes\":[],...}")
	}
}

func TestRenderHTMLContainsData(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()
	var out bytes.Buffer
	if err := RenderHTML(g, &out); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	h := out.String()
	// Check for workload node IDs (now inside the {"nodes":[...],"edges":[...]} wrapper)
	if !strings.Contains(h, "\"default/nginx\"") {
		t.Error("output missing workload node id default/nginx")
	}
	if !strings.Contains(h, "\"default/redis\"") {
		t.Error("output missing workload node id default/redis")
	}
	// Check for edge protocol/port info in JSON data
	if !strings.Contains(h, "\"TCP\"") {
		t.Error("output missing protocol TCP")
	}
	if !strings.Contains(h, "6379") {
		t.Error("output missing port 6379")
	}
	if !strings.Contains(h, "80") {
		t.Error("output missing port 80")
	}
	// Verify classes are present in the JSON (node classes)
	if !strings.Contains(h, "\"classes\":\"workload\"") {
		t.Error("output missing node classes field with 'workload' class")
	}
	if !strings.Contains(h, "\"classes\":\"reserved\"") {
		t.Error("output missing node classes field with 'reserved' class")
	}
	// Verify edge direction classes
	if !strings.Contains(h, "\"classes\":\"ingress\"") {
		t.Error("output missing edge classes field with 'ingress' class")
	}
	if !strings.Contains(h, "\"classes\":\"egress\"") {
		t.Error("output missing edge classes field with 'egress' class")
	}
}

// TestRenderHTMLFixedBugs validates the three inline-fix variants (A/B/C/D)
// that were empirically proven in a headless Chromium run (0 page errors,
// all nodes+edges visible, deterministic container height).
func TestRenderHTMLFixedBugs(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()
	var out bytes.Buffer
	if err := RenderHTML(g, &out); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	h := out.String()

	// FIX 1 — IIFE script in <body> (after #cy div), not in <head>.
	// The div with id="cy" must serialize before the 'use strict' IIFE.
	if hIdx, sIdx := strings.Index(h, `id="cy"`), strings.Index(h, "'use strict'"); hIdx < 0 || sIdx < 0 || hIdx > sIdx {
		t.Error("FIX1 FAIL: IIFE ('use strict') appears before or at the same position as id=\"cy\" — script still in <head>")
	}

	// FIX 2 — node.reserved, node.cidr, node.selector each carry a
	// 'content':function(e){...} mapper so label-sized nodes take up space.
	// (node.workload already had it before these fixes.)
	// We assert >= 3 (reserved + cidr + selector).
	contentCount := strings.Count(h, "'content':function(e){return e.data('label')||''")
	if contentCount < 3 {
		t.Errorf("FIX2 FAIL: found %d content mappers for label-sized nodes, need >= 3 (reserved/cidr/selector)", contentCount)
	}

	// FIX 3 — #graph-wrapper gets height:100%;overflow:hidden so the
	// Cytoscape canvas does not create an unbounded grid-row loop.
	if !strings.Contains(h, "#graph-wrapper{height:100%;overflow:hidden}") {
		t.Error("FIX3 FAIL: #graph-wrapper height/overflow rule missing")
	}

	// FIX 4 — Cytoscape's pstyle() does not resolve CSS custom properties.
	// Extract the style array region and assert it contains ZERO var(--.
	styleStart := strings.Index(h, "style:[")
	styleEnd := strings.Index(h, "layout:{name:'dagre'}")
	if styleStart >= 0 && styleEnd > styleStart {
		styleRegion := h[styleStart:styleEnd]
		if strings.Contains(styleRegion, "var(--") {
			t.Error("FIX4 FAIL: CSS custom properties (var(--) found inside Cytoscape style array — colors will fall back to default gray")
		}
		if !strings.Contains(styleRegion, "'line-color':'#8b5cf6'") {
			t.Error("FIX4 FAIL: edge.ingress line-color not set to #8b5cf6 (purple)")
		}
		if !strings.Contains(styleRegion, "'line-color':'#38bdf8'") {
			t.Error("FIX4 FAIL: edge.egress line-color not set to #38bdf8 (blue)")
		}
	}

	// FIX 5 — base edge style has no content mapper; edges render with
	// content: null so no labels appear. Assert protocol:port mapper exists.
	if !strings.Contains(h, "data('protocol')") {
		t.Error("FIX5 FAIL: edge content mapper missing data('protocol')")
	}
	if !strings.Contains(h, "data('port')") {
		t.Error("FIX5 FAIL: edge content mapper missing data('port')")
	}

	// FIX 6 — dagre crashes on parallel edges (assignOrder 'order' on undefined).
	// Edges are merged by (source,target,direction) client-side before layout.
	if !strings.Contains(h, "MERGE_PARALLEL_EDGES") {
		t.Error("FIX6 FAIL: parallel-edge merge code missing from template")
	}
	if !strings.Contains(h, "e.data('label')||") {
		t.Error("FIX6 FAIL: edge content mapper does not prefer merged label")
	}

	// FIX 7 — round-2 user-issue fixes.
	if !strings.Contains(h, "flowGuarder") {
		t.Error("FIX7 FAIL: header does not contain flowGuarder (capital G)")
	}
	if !strings.Contains(h, "n.connectedEdges().style('display','')") {
		t.Error("FIX7 FAIL: search fix n.connectedEdges() missing")
	}
	if strings.Contains(h, "cy.png({full:true,output:'base64url'}).then(") {
		t.Error("FIX7 FAIL: export still uses .then() on synchronous cy.png")
	}
	if !strings.Contains(h, "'label':'data(label)'") {
		t.Error("FIX7 FAIL: namespace compartment label mapper missing")
	}
	if !strings.Contains(h, "dn.data.kind==='namespace'&&dn.data.id") {
		t.Error("FIX7 FAIL: initNsExpanded does not read dn.data.kind")
	}
	if !strings.Contains(h, "btn-show-all") {
		t.Error("FIX7 FAIL: Show-all button missing")
	}
}

func TestRenderHTMLWithSource(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()

	t.Run("source contains special chars", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, "demo<.jsonl"); err != nil {
			t.Fatalf("RenderHTMLWithSource: %v", err)
		}
		h := out.String()
		if !strings.Contains(h, `demo\u003c.jsonl`) {
			t.Errorf("source not JSON-escaped into output")
		}
	})

	t.Run("source placeholder replaced", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, "demo<.jsonl"); err != nil {
			t.Fatalf("RenderHTMLWithSource: %v", err)
		}
		if strings.Contains(out.String(), "__SOURCE__") {
			t.Error("__SOURCE__ placeholder not replaced")
		}
	})

	t.Run("empty source", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, ""); err != nil {
			t.Fatalf("RenderHTMLWithSource(empty): %v", err)
		}
		if strings.Contains(out.String(), "__SOURCE__") {
			t.Error("empty source: __SOURCE__ placeholder still present")
		}
	})
}
