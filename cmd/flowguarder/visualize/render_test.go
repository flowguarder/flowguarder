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

// allLayoutModes enumerates every mode for table-driven coverage.
func allLayoutModes() []struct {
	name string
	mode LayoutMode
} {
	return []struct {
		name string
		mode LayoutMode
	}{
		{"straight", ModeStraight},
		{"orthogonal", ModeOrthogonal},
		{"curved", ModeCurved},
	}
}

// renderMode renders g in the given mode and returns the output bytes.
func renderMode(t *testing.T, g Graph, mode LayoutMode, source string) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := RenderHTMLWithSource(g, &out, source, mode); err != nil {
		t.Fatalf("RenderHTMLWithSource(%s): %v", mode, err)
	}
	return out.Bytes()
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
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := fixtureGraph()
			h := string(renderMode(t, g, tc.mode, ""))
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
		})
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

// TestRenderHTMLPerModeDeterminism proves byte-level determinism of every
// layout mode: two renders from identical input must be identical.
func TestRenderHTMLPerModeDeterminism(t *testing.T) {
	t.Parallel()
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := fixtureGraph()
			first := renderMode(t, g, tc.mode, "demo.jsonl")
			second := renderMode(t, g, tc.mode, "demo.jsonl")
			if !bytes.Equal(first, second) {
				t.Errorf("two %s renders of the same graph produced different output (%d vs %d bytes)",
					tc.mode, len(first), len(second))
			}
		})
	}
}

func TestRenderHTMLEmptyGraph(t *testing.T) {
	t.Parallel()
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			empty := Graph{}
			h := string(renderMode(t, empty, tc.mode, ""))
			if !strings.Contains(h, "<!DOCTYPE html>") {
				t.Error("empty graph output missing DOCTYPE")
			}
			if !strings.Contains(h, "html") {
				t.Error("empty graph output missing html tag")
			}
		})
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

	h := renderMode(t, g, ModeStraight, "")
	if len(h) <= 100*1024 {
		t.Errorf("output size %d bytes, expected > 100KB", len(h))
	}
	// Payload guard (binding spec): straight output stays under 500KB total.
	if len(h) >= 500*1024 {
		t.Errorf("straight output size %d bytes, expected < 500KB", len(h))
	}
}

func TestRenderHTMLDataShape(t *testing.T) {
	t.Parallel()
	// The graph data must be a {"nodes":[],"edges":[]} object assigned
	// to a var in an inline script — not a bare nested-array concat.
	g := fixtureGraph()
	h := string(renderMode(t, g, ModeStraight, ""))
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
	h := string(renderMode(t, g, ModeStraight, ""))
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

// TestRenderHTMLFixedBugs validates the inline-fix variants (A/B/C/D)
// that were empirically proven in a headless Chromium run (0 page errors,
// all nodes+edges visible, deterministic container height).
//
// FIX4 (dagre-delimiter style-region extraction) was RETIRED: the template
// uses the preset construction layout and no longer contains any dagre
// delimiter; per-mode edge-color assertions live in
// TestRenderHTMLPerModeEdgeStyles instead.
func TestRenderHTMLFixedBugs(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()
	h := string(renderMode(t, g, ModeStraight, ""))

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

	// FIX 5 — base edge style has no content mapper; edges render with
	// content: null so no labels appear. Assert protocol:port mapper exists.
	if !strings.Contains(h, "data('protocol')") {
		t.Error("FIX5 FAIL: edge content mapper missing data('protocol')")
	}
	if !strings.Contains(h, "data('port')") {
		t.Error("FIX5 FAIL: edge content mapper missing data('port')")
	}

	// FIX 6 — parallel edges are merged by (source,target,direction)
	// client-side before layout. Asserted for ALL modes in
	// TestRenderHTMLPerModeInvariants.

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

// TestRenderHTMLPerModeInvariants asserts, for EVERY layout mode:
//   - MERGE_PARALLEL_EDGES semantics survive (FIX6);
//   - the merged-label preference survives;
//   - every placeholder and mode sentinel is fully replaced/stripped;
//   - the `  positionNsButtons();` anchor inside init() remains unique
//     (downstream dev-hook injector + parity gate grep this exact line);
//   - the injected VIZ_MODE constant carries the rendered mode.
func TestRenderHTMLPerModeInvariants(t *testing.T) {
	t.Parallel()
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := fixtureGraph()
			h := string(renderMode(t, g, tc.mode, "demo.jsonl"))

			// FIX6 — MERGE_PARALLEL_EDGES + merged label preference.
			if !strings.Contains(h, "MERGE_PARALLEL_EDGES") {
				t.Error("FIX6 FAIL: parallel-edge merge code missing from template")
			}
			if !strings.Contains(h, "e.data('label')||") {
				t.Error("FIX6 FAIL: edge content mapper does not prefer merged label")
			}

			// Placeholder/sentinel coverage: zero occurrences post-render.
			for _, ph := range []string{
				"__VIZ_MODE__",
				"__ENGINE_JS__",
				"__CYTOSCAPE_JS__",
				"__GRAPH_DATA__",
				"__NAMESPACES__",
				"__PROTOCOLS__",
				"__DIRECTIONS__",
				"__SOURCE__",
				"{{FG_STRAIGHT}}",
				"{{FG_NONSTRAIGHT}}",
				"{{FG_ORTHO}}",
				"{{FG_CURVED}}",
			} {
				if strings.Contains(h, ph) {
					t.Errorf("placeholder/sentinel %q not fully replaced", ph)
				}
			}

			// Injected mode constant matches the requested mode.
			wantMode := `var VIZ_MODE="` + string(tc.mode) + `";`
			if !strings.Contains(h, wantMode) {
				t.Errorf("output missing injected constant %s", wantMode)
			}

			// Anchor uniqueness (dev-hook injector + todo-9 parity gate).
			if n := strings.Count(h, "positionNsButtons();"); n != 1 {
				t.Errorf("anchor 'positionNsButtons();' found %d times, want exactly 1", n)
			}
		})
	}
}

// TestRenderHTMLModeAssetExclusivity asserts each generated file embeds ONLY
// its own mode's engine assets:
//   - straight: zero elkjs markers, zero dagre markers, no ELK code;
//   - orthogonal/curved: elkjs marker present (bundle + attribution),
//     zero dagre markers; curved additionally ships the lane-split helper,
//     orthogonal must not.
func TestRenderHTMLModeAssetExclusivity(t *testing.T) {
	t.Parallel()
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := fixtureGraph()
			h := string(renderMode(t, g, tc.mode, ""))

			if n := strings.Count(h, "elkjs"); n == 0 && tc.mode != ModeStraight {
				t.Errorf("%s output has zero elkjs markers, want >= 1", tc.mode)
			}
			if n := strings.Count(h, "elkjs"); n != 0 && tc.mode == ModeStraight {
				t.Errorf("straight output contains %d elkjs markers, want 0", n)
			}
			if n := strings.Count(h, "dagre"); n != 0 {
				t.Errorf("%s output contains %d dagre markers, want 0", tc.mode, n)
			}
			if tc.mode == ModeStraight {
				if strings.Contains(h, "new ELK") || strings.Contains(h, "fgDeOverlap") ||
					strings.Contains(h, "'curve-style':'taxi'") ||
					strings.Contains(h, "'curve-style':'unbundled-bezier'") {
					t.Error("straight output contains non-straight engine code")
				}
			}
			if tc.mode == ModeOrthogonal {
				if !strings.Contains(h, "'curve-style':'taxi'") {
					t.Error("orthogonal output missing taxi curve-style")
				}
				// Bare "unbundled-bezier" also occurs inside Cytoscape itself — match template syntax only.
				if strings.Contains(h, "function fgLaneAssign") ||
					strings.Contains(h, "'curve-style':'unbundled-bezier'") ||
					strings.Contains(h, "'control-point-distances':'data(cpd)'") {
					t.Error("orthogonal output contains curved-only lane-split code")
				}
			}
			if tc.mode == ModeCurved {
				if !strings.Contains(h, "'curve-style':'unbundled-bezier'") {
					t.Error("curved output missing unbundled-bezier curve-style")
				}
				if !strings.Contains(h, "function fgLaneAssign()") {
					t.Error("curved output missing fgLaneAssign helper")
				}
			}
			// elkjs attribution (GPL-3.0-or-later chosen term) rides with the
			// ELK payload only — never in straight output.
			hasAttrib := strings.Contains(h, "GPL-3.0-or-later") &&
				strings.Contains(h, "Kiel University")
			if tc.mode == ModeStraight && hasAttrib {
				t.Error("straight output contains elkjs attribution, want none")
			}
			if tc.mode != ModeStraight && !hasAttrib {
				t.Errorf("%s output missing elkjs attribution string", tc.mode)
			}
		})
	}
}

// TestRenderHTMLPerModeEdgeStyles replaces the retired FIX4 assertions: the
// style region is extracted via the stable preset-layout delimiter (no dagre
// delimiter exists anymore) and edge direction colors are asserted per mode.
func TestRenderHTMLPerModeEdgeStyles(t *testing.T) {
	t.Parallel()
	for _, tc := range allLayoutModes() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := fixtureGraph()
			h := string(renderMode(t, g, tc.mode, ""))

			styleStart := strings.Index(h, "style:[")
			styleEnd := strings.Index(h, "layout:{name:'preset'}")
			if styleStart < 0 || styleEnd <= styleStart {
				t.Fatal("could not locate Cytoscape style region")
			}
			region := h[styleStart:styleEnd]

			if strings.Contains(region, "var(--") {
				t.Error("CSS custom properties (var(--) found inside Cytoscape style array — colors will fall back to default gray")
			}
			// Egress blue is shared by every mode.
			if !strings.Contains(region, "'line-color':'#38bdf8'") {
				t.Error("edge.egress line-color not set to #38bdf8 (blue)")
			}
			switch tc.mode {
			case ModeStraight:
				if !strings.Contains(region, "'line-color':'#8b5cf6'") {
					t.Error("straight edge.ingress line-color not set to #8b5cf6 (purple)")
				}
				if strings.Contains(region, "#a78bfa") {
					t.Error("straight output contains ELK-mode ingress color #a78bfa")
				}
			default:
				if !strings.Contains(region, "'line-color':'#a78bfa'") {
					t.Errorf("%s edge.ingress line-color not set to #a78bfa", tc.mode)
				}
				if strings.Contains(region, "#8b5cf6") {
					t.Errorf("%s output contains straight-only ingress color #8b5cf6", tc.mode)
				}
			}
		})
	}
}

func TestRenderHTMLWithSource(t *testing.T) {
	t.Parallel()
	g := fixtureGraph()

	t.Run("source contains special chars", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, "demo<.jsonl", ModeStraight); err != nil {
			t.Fatalf("RenderHTMLWithSource: %v", err)
		}
		h := out.String()
		if !strings.Contains(h, `demo\u003c.jsonl`) {
			t.Errorf("source not JSON-escaped into output")
		}
	})

	t.Run("source placeholder replaced", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, "demo<.jsonl", ModeStraight); err != nil {
			t.Fatalf("RenderHTMLWithSource: %v", err)
		}
		if strings.Contains(out.String(), "__SOURCE__") {
			t.Error("__SOURCE__ placeholder not replaced")
		}
	})

	t.Run("empty source", func(t *testing.T) {
		var out bytes.Buffer
		if err := RenderHTMLWithSource(g, &out, "", ModeStraight); err != nil {
			t.Fatalf("RenderHTMLWithSource(empty): %v", err)
		}
		if strings.Contains(out.String(), "__SOURCE__") {
			t.Error("empty source: __SOURCE__ placeholder still present")
		}
	})

	t.Run("mode parameter changes output", func(t *testing.T) {
		straight := renderMode(t, g, ModeStraight, "")
		ortho := renderMode(t, g, ModeOrthogonal, "")
		curved := renderMode(t, g, ModeCurved, "")
		if bytes.Equal(straight, ortho) || bytes.Equal(straight, curved) || bytes.Equal(ortho, curved) {
			t.Error("distinct modes produced identical output")
		}
	})
}

// TestStripModeSections covers the stripper directly: unknown-but-balanced
// templates pass through untouched for a mode that keeps everything, and an
// unbalanced sentinel is an error rather than silent corruption.
func TestStripModeSections(t *testing.T) {
	t.Parallel()

	t.Run("unbalanced open is an error", func(t *testing.T) {
		t.Parallel()
		bad := []byte("/*{{FG_ORTHO}}*/never closed")
		if _, err := stripModeSections(bad, ModeStraight); err == nil {
			t.Error("expected error for unclosed section")
		}
	})

	t.Run("no sections is identity", func(t *testing.T) {
		t.Parallel()
		in := []byte("<p>nothing here</p>")
		out, err := stripModeSections(in, ModeCurved)
		if err != nil {
			t.Fatalf("stripModeSections: %v", err)
		}
		if !bytes.Equal(in, out) {
			t.Error("section-free template was modified")
		}
	})
}
