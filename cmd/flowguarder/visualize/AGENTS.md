# cmd/flowguarder/visualize — Policy Graph Visualization

## OVERVIEW
Extracts a deterministic directed graph from `[]policy.Policy` objects and renders a self-contained offline HTML page in THREE layout modes: `straight` (Cytoscape-only preset+multi-phase), `orthogonal` + `curved` (ELK layered via inlined `elk.bundled-0.12.0.js`). Mode chosen by `SelectLayoutMode` or explicit flag (`--viz-layout`). Zero CDN.

## STRUCTURE
| File | Lines | Purpose |
|---|---|---|
| `model.go` | 410 | `Node` (ID, Label, Kind, Namespace, Parent), `Edge` (Source, Target, Direction, Protocol, Port, Description), `Graph` (Nodes, Edges). Five `NodeKind` constants. `BuildGraph([]policy.Policy) Graph` — main entry (~line 183). Helpers: `classifyPeer`, `isCIDRLike`, `ensureNs`, `ensureWorkload`, `nodeLess`, `sortAllNodes`, `edgeLess`, `sortAllEdges`. |
| `render.go` | 335 | `RenderHTMLWithSource(Graph, io.Writer, source string, mode LayoutMode)` — strips per-mode `/*{{FG_*}}*/` sentinel sections, replaces placeholders in fixed order (cytoscape → engine slot only for ortho/curved → graph/ns/proto/dir/source → quoted VIZ_MODE token). `RenderHTML(g,w)` = test-only delegate pinned ModeStraight. Doc comment carries elkjs attribution. |
| `layoutmode.go` | 59 | `LayoutMode` type; `ModeStraight`/`ModeOrthogonal`/`ModeCurved`. `SelectLayoutMode(nodes, edges, manual)`: binding thresholds E≤250∧N≤180→curved else orthogonal for auto; explicit straight/ortho/curved wins at any size; ""≡auto; strict lowercase; error lists auto\|straight\|orthogonal\|curved. |
| `layoutmode_test.go` | 110 | Threshold binding cells, manual override, strict validation errors. |
| `render_test.go` | 552 | Per-mode determinism (double-render byte equality), asset-exclusivity greps, sentinel stripping tests, anchor uniqueness. |
| `model_test.go` | 1,002 | BuildGraph graph correctness, peer classification, dedup, sorting, port-mutation guard. |
| `edge_cases_test.go` | 533 | Empty inputs, WorkloadID without "/", mixed selector/cidr/reserved peers. |

Assets: `assets/` — EXACTLY `cytoscape.min.js` + `elk.bundled-0.12.0.js` (dagre.min.js and cytoscape-dagre.min.js DELETED). elkjs license: EPL-2.0 OR GPL-3.0-or-later, GPL term chosen; attribution block lives in render.go doc comment AND template header inside FG_NONSTRAIGHT span (straight output must grep ZERO "elkjs"). Template: `template.html` (~1185 lines).

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add/change node kinds | `model.go` NodeKind constants + `classifyPeer` |
| Change graph construction logic | `BuildGraph` (model.go ~line 183) |
| Change layout thresholds | `layoutmode.go` `SelectLayoutMode` + `layoutmode_test.go` binding cells |
| Change per-mode engine code | `template.html` FG_ORTHO / FG_CURVED / FG_NONSTRAIGHT spans |
| Change HTML/CSS/JS or embedding | `render.go` + `assets/` + `template.html` |
| Badge/header label | `../common_pipeline.go` `vizSourceLabel` |
| Change viz write behavior (atomicity, chmod, skip) | `../common_pipeline.go` `writeVisualizationHTML` (~line 438) |
| Verify determinism | `../common_pipeline_test.go` (HTML byte-for-byte assertions) |

## CONVENTIONS
- Pure + deterministic: `BuildGraph` returns sorted Graph. Nodes sorted by (Kind, ID). Edges by (Source, Target, Direction, Protocol, Port). No `time.Now`, no random IDs.
- Input `[]policy.Policy` is never mutated (test: `TestNoPortMutation` in `model_test.go`).
- Deterministic output per (graph, source, mode); double-render byte-equality tested per mode.
- Entry point: `writeVisualizationHTML` in `../common_pipeline.go` calls `BuildGraph` + `SelectLayoutMode` + `RenderHTMLWithSource`, writes atomically (temp file + rename), chmod 0644.
- Errors are non-blocking: viz write failure returns error up the pipeline but doesn't abort policy generation.
- Fully offline gate test bans src/href http(s); all JS is `go:embed`ded at build time.
- Template UI features are mode-shared, outside sentinels: topbar brand logo (base64 data URI img), edge highlighting (`edge.hl`/`edge.dim`, clearHighlights(), tap node/edge/canvas), collapsible Details panel (#details-toggle), zoom controls.

## ANTI-PATTERNS
- No external CDN references or resource-loading constructs — air-gapped requirement.
- No timestamps, random IDs, or non-deterministic ordering in output.
- Do NOT mutate the input `[]policy.Policy` slice.
- Do NOT put I/O or network access inside `model.go` — it is pure graph construction.
- Do NOT break the `  positionNsButtons();` anchor line uniqueness (external tooling greps it).
- Do NOT let straight output contain "elkjs"/"dagre" markers.
- Do NOT re-add dagre assets.
