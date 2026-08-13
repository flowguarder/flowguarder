// Package visualize extracts a deterministic directed graph from policy
// objects and renders it as an offline, self-contained HTML page.
//
// The HTML embeds Cytoscape.js, dagre, and cytoscape-dagre — no CDN
// references — so it works completely offline.
//
// Architecture: an HTML template file (template.html) is embedded via go:embed.
// Placeholder tokens (e.g. __CYTOSCAPE_JS__) are replaced at runtime with
// embedded asset bytes and marshalled graph data using bytes.ReplaceAll.
// Never use Go string constants for HTML/JS — keep templating in the HTML file.
//
// License attribution:
//
//	Cytoscape.js — The MIT License.
//	Copyright (c) 2016-2026, The Cytoscape Consortium.
//
//	Dagre — The MIT License.
//	Copyright (c) 2012-2014, Chris Pettitt.
//
//	cytoscape-dagre — The MIT License.
//	(bundled under Cytoscape.js terms)
//
// All three libraries are included under The MIT License:
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

//go:embed assets/dagre.min.js
var dagreBytes []byte

//go:embed assets/cytoscape-dagre.min.js
var cytoscapeDagreBytes []byte

// Template placeholder tokens (must match template.html).
const (
	phCytoscape  = "__CYTOSCAPE_JS__"
	phDagre      = "__DAGRE_JS__"
	phCyDagre    = "__CYTO_DAGRE_JS__"
	phGraph      = "__GRAPH_DATA__"
	phNamespaces = "__NAMESPACES__"
	phProtocols  = "__PROTOCOLS__"
	phDirections = "__DIRECTIONS__"
	phSource     = "__SOURCE__"
)

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

// RenderHTMLWithSource renders the graph with an optional source string.
func RenderHTMLWithSource(g Graph, w io.Writer, source string) error {
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

	// 7. Replace placeholders in the template in a FIXED order.
	out := templateFS
	out = bytesReplace(out, phCytoscape, cytoscapeBytes)
	out = bytesReplace(out, phDagre, dagreBytes)
	out = bytesReplace(out, phCyDagre, cytoscapeDagreBytes)
	out = bytesReplace(out, phGraph, graphJSON)
	out = bytesReplace(out, phNamespaces, nsJSON)
	out = bytesReplace(out, phProtocols, protoJSON)
	out = bytesReplace(out, phDirections, dirJSON)
	out = bytesReplace(out, phSource, sourceJSON)

	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// RenderHTML renders the graph (no source) — delegates to RenderHTMLWithSource.
func RenderHTML(g Graph, w io.Writer) error {
	return RenderHTMLWithSource(g, w, "")
}

// bytesReplace replaces a placeholder comment with raw bytes.
func bytesReplace(buf []byte, placeholder string, replacement []byte) []byte {
	target := []byte("/* " + placeholder + " */")
	return bytes.ReplaceAll(buf, target, replacement)
}
