// Package visualize extracts a deterministic directed graph from policy
// objects and renders it as an offline, self-contained HTML page.
//
// The HTML embeds Cytoscape.js — no CDN references — so it works completely
// offline. Three layout modes exist (see LayoutMode): "straight" embeds
// Cytoscape only, while "orthogonal" and "curved" additionally embed the
// elkjs bundle used by their layout engines. Each generated file carries
// ONLY its own mode's assets.
//
// Architecture: an HTML template file (template.html) is embedded via go:embed.
// Placeholder tokens (e.g. __CYTOSCAPE_JS__) are replaced at runtime with
// embedded asset bytes and marshalled graph data using bytes.ReplaceAll.
// Mode-specific template sections delimited by /*{{FG_*}}*/ ... /*{{/FG_*}}*/
// sentinels are stripped per mode before substitution. Never use Go string
// constants for HTML/JS — keep templating in the HTML file.
//
// License attribution:
//
//	Cytoscape.js — The MIT License.
//	Copyright (c) 2016-2026, The Cytoscape Consortium.
//
//	elkjs 0.12.0 (lib/elk.bundled.js) — dual-licensed under
//	EPL-2.0 OR GPL-3.0-or-later (SPDX, per package.json).
//	The GPL-3.0-or-later term is chosen for this derivative;
//	flowguarder is GPL-3.0, so distribution under flowguarder's
//	GPL-3.0 satisfies the chosen term. No EPL-2.0 obligations attach.
//	Copyright (c) Kiel University, sreal-software-solutions GmbH
//	and contributors. Source: https://github.com/kieler/elkjs
//
// Cytoscape.js is included under The MIT License:
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
package visualize

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

//go:embed template.html
var templateFS []byte

//go:embed assets/cytoscape.min.js
var cytoscapeBytes []byte

//go:embed assets/elk.bundled-0.12.0.js
var elkBytes []byte

// Template placeholder tokens (must match template.html).
const (
	phCytoscape  = "__CYTOSCAPE_JS__"
	phElk        = "__ENGINE_JS__"
	phGraph      = "__GRAPH_DATA__"
	phNamespaces = "__NAMESPACES__"
	phProtocols  = "__PROTOCOLS__"
	phDirections = "__DIRECTIONS__"
	phSource     = "__SOURCE__"
	phVizMode    = "__VIZ_MODE__"
)

// modeSection describes a delimited template region belonging to a subset of
// layout modes. The sentinels are JS block comments, so any surviving region
// stays syntactically valid after stripping.
type modeSection struct {
	open  string
	close string
	keep  func(mode LayoutMode) bool
}

// Template mode sections. FG_NONSTRAIGHT regions carry the ELK layout core
// shared by orthogonal and curved; FG_ORTHO/FG_CURVED carry per-mode deltas;
// FG_STRAIGHT wraps the legacy preset+multi-phase runner.
var modeSections = []modeSection{
	{open: "/*{{FG_NONSTRAIGHT}}*/", close: "/*{{/FG_NONSTRAIGHT}}*/",
		keep: func(m LayoutMode) bool { return m == ModeOrthogonal || m == ModeCurved }},
	{open: "/*{{FG_ORTHO}}*/", close: "/*{{/FG_ORTHO}}*/",
		keep: func(m LayoutMode) bool { return m == ModeOrthogonal }},
	{open: "/*{{FG_CURVED}}*/", close: "/*{{/FG_CURVED}}*/",
		keep: func(m LayoutMode) bool { return m == ModeCurved }},
	{open: "/*{{FG_STRAIGHT}}*/", close: "/*{{/FG_STRAIGHT}}*/",
		keep: func(m LayoutMode) bool { return m == ModeStraight }},
}

// stripModeSections removes every non-active section (sentinels included) and
// unwraps active sections (sentinels removed, content kept). Pure and
// deterministic; errors if a sentinel pair is unbalanced.
func stripModeSections(tmpl []byte, mode LayoutMode) ([]byte, error) {
	out := tmpl
	for _, sec := range modeSections {
		for {
			i := bytes.Index(out, []byte(sec.open))
			if i < 0 {
				break
			}
			j := bytes.Index(out[i+len(sec.open):], []byte(sec.close))
			if j < 0 {
				return nil, fmt.Errorf("template section %q opened but never closed", sec.open)
			}
			j += i + len(sec.open)
			if sec.keep(mode) {
				merged := append([]byte{}, out[:i]...)
				merged = append(merged, out[i+len(sec.open):j]...)
				merged = append(merged, out[j+len(sec.close):]...)
				out = merged
			} else {
				merged := append([]byte{}, out[:i]...)
				merged = append(merged, out[j+len(sec.close):]...)
				out = merged
			}
		}
	}
	return out, nil
}

// graphDataDTO is the single JSON object the app script reads as GRAPH_DATA.
// Keys match the lower-cased struct fields (Go serializes as "nodes"/"edges").
type graphDataDTO struct {
	Nodes []nodeDTO `json:"nodes"`
	Edges []edgeDTO `json:"edges"`
}

// nodeDTO is the JSON serialisation of a graph node for Cytoscape consumption.
// Classes drive the CSS style selectors (node.compartment, node.workload, etc.).
type nodeDTO struct {
	Group string `json:"group"`
	Data  struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace,omitempty"`
		Parent    string `json:"parent,omitempty"`
	} `json:"data"`
	Classes string `json:"classes"`
}

// edgeDTO is the JSON serialisation of a graph edge for Cytoscape consumption.
type edgeDTO struct {
	Group string `json:"group"`
	Data  struct {
		ID          string `json:"id"`
		Source      string `json:"source"`
		Target      string `json:"target"`
		Direction   string `json:"direction"`
		Protocol    string `json:"protocol"`
		Port        uint16 `json:"port"`
		Description string `json:"description"`
	} `json:"data"`
	Classes string `json:"classes"`
}

// nodeClasses returns the Cytoscape class string for a node kind.
func nodeClasses(kind NodeKind) string {
	switch kind {
	case NamespaceKind:
		return "compartment"
	case WorkloadKind:
		return "workload"
	case ReservedKind:
		return "reserved"
	case CIDRKind:
		return "cidr"
	case SelectorKind:
		return "selector"
	default:
		return ""
	}
}

// RenderHTMLWithSource renders the graph with an optional source string in the
// given layout mode. The mode selects which engine assets are embedded:
// straight ships Cytoscape only; orthogonal and curved additionally inline the
// elkjs bundle. Output is deterministic per (graph, source, mode).
func RenderHTMLWithSource(g Graph, w io.Writer, source string, mode LayoutMode) error {
	tmpl, err := stripModeSections(templateFS, mode)
	if err != nil {
		return fmt.Errorf("strip mode sections: %w", err)
	}

	// 1. Marshal nodes to Cytoscape-formatted DTOs (with classes for style selectors).
	nodeDTOs := make([]nodeDTO, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		dto := nodeDTO{
			Group:   "nodes",
			Classes: nodeClasses(n.Kind),
			Data: struct {
				ID        string `json:"id"`
				Label     string `json:"label"`
				Kind      string `json:"kind"`
				Namespace string `json:"namespace,omitempty"`
				Parent    string `json:"parent,omitempty"`
			}{
				ID:        n.ID,
				Label:     n.Label,
				Kind:      string(n.Kind),
				Namespace: n.Namespace,
				Parent:    n.Parent,
			},
		}
		nodeDTOs = append(nodeDTOs, dto)
	}

	// 2. Marshal edges to Cytoscape-formatted DTOs with deterministic IDs.
	edgeDTOs := make([]edgeDTO, 0, len(g.Edges))
	for i, e := range g.Edges {
		dto := edgeDTO{
			Group:   "edges",
			Classes: e.Direction, // "ingress" or "egress" — drives style selectors
			Data: struct {
				ID          string `json:"id"`
				Source      string `json:"source"`
				Target      string `json:"target"`
				Direction   string `json:"direction"`
				Protocol    string `json:"protocol"`
				Port        uint16 `json:"port"`
				Description string `json:"description"`
			}{
				ID:          fmt.Sprintf("e%d", i),
				Source:      e.Source,
				Target:      e.Target,
				Direction:   e.Direction,
				Protocol:    e.Protocol,
				Port:        e.Port,
				Description: e.Description,
			},
		}
		edgeDTOs = append(edgeDTOs, dto)
	}

	// 3. Marshal the single {nodes:[],edges:[]} object.
	graphDTO := graphDataDTO{Nodes: nodeDTOs, Edges: edgeDTOs}
	graphJSON, err := json.Marshal(graphDTO)
	if err != nil {
		return fmt.Errorf("marshal graph data: %w", err)
	}

	// 4. Collect distinct namespaces, protocols, directions — sorted.
	namespaces := make([]string, 0)
	seenNS := make(map[string]bool)
	for _, n := range g.Nodes {
		if n.Namespace != "" && !seenNS[n.Namespace] {
			seenNS[n.Namespace] = true
			namespaces = append(namespaces, n.Namespace)
		}
	}
	slices.Sort(namespaces)

	protos := make([]string, 0)
	seenP := make(map[string]bool)
	for _, e := range g.Edges {
		if e.Protocol != "" && !seenP[e.Protocol] {
			seenP[e.Protocol] = true
			protos = append(protos, e.Protocol)
		}
	}
	slices.Sort(protos)

	dirs := make([]string, 0)
	seenD := make(map[string]bool)
	for _, e := range g.Edges {
		if e.Direction != "" && !seenD[e.Direction] {
			seenD[e.Direction] = true
			dirs = append(dirs, e.Direction)
		}
	}
	slices.Sort(dirs)

	// 5. Marshal filter lists.
	nsJSON, _ := json.Marshal(namespaces)
	protoJSON, _ := json.Marshal(protos)
	dirJSON, _ := json.Marshal(dirs)

	// 6. Marshal source (HTML-escaped for safe embedding).
	sourceJSON, _ := json.Marshal(source)

	// 7. Marshal the mode as a quoted JSON string literal.
	modeJSON, _ := json.Marshal(string(mode))

	// 8. Replace placeholders in the template in a FIXED order. The engine
	// slot receives the ELK bundle only for ELK-backed modes; straight leaves
	// it empty so no engine bytes ship.
	out := tmpl
	out = bytesReplace(out, phCytoscape, cytoscapeBytes)
	if mode == ModeOrthogonal || mode == ModeCurved {
		out = bytesReplace(out, phElk, elkBytes)
	} else {
		out = bytesReplace(out, phElk, nil)
	}
	out = bytesReplace(out, phGraph, graphJSON)
	out = bytesReplace(out, phNamespaces, nsJSON)
	out = bytesReplace(out, phProtocols, protoJSON)
	out = bytesReplace(out, phDirections, dirJSON)
	out = bytesReplace(out, phSource, sourceJSON)
	out = bytesReplaceToken(out, phVizMode, modeJSON)

	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// RenderHTML renders the graph (no source) — delegates to RenderHTMLWithSource
// pinned to ModeStraight. Test-only convenience.
func RenderHTML(g Graph, w io.Writer) error {
	return RenderHTMLWithSource(g, w, "", ModeStraight)
}

// bytesReplace replaces a placeholder comment with raw bytes.
func bytesReplace(buf []byte, placeholder string, replacement []byte) []byte {
	target := []byte("/* " + placeholder + " */")
	return bytes.ReplaceAll(buf, target, replacement)
}

// bytesReplaceToken replaces a bare placeholder token (no comment wrapping).
func bytesReplaceToken(buf []byte, token string, replacement []byte) []byte {
	return bytes.ReplaceAll(buf, []byte(token), replacement)
}
