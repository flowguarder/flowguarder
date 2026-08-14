# cmd/flowguarder/visualize — Policy Graph Visualization

## OVERVIEW
Extracts a deterministic directed graph from `[]policy.Policy` objects and renders it as a self-contained
offline HTML page (Cytoscape.js + dagre inlined, zero CDN).

## STRUCTURE
| File | Lines | Purpose |
|---|---|---|
| `model.go` | 410 | `Node` (ID, Label, Kind, Namespace, Parent), `Edge` (Source, Target, Direction, Protocol, Port, Description), `Graph` (Nodes, Edges). Five `NodeKind` constants. `BuildGraph([]policy.Policy) Graph` — main entry (~line 183). Helpers: `classifyPeer`, `isCIDRLike`, `ensureNs`, `ensureWorkload`, `nodeLess`, `sortAllNodes`, `edgeLess`, `sortAllEdges`. |
| `render.go` | 254 | `RenderHTMLWithSource(Graph, io.Writer, string)` — embeds template.html + 3 JS libs via `go:embed`, replaces placeholder tokens, writes to `io.Writer`. `RenderHTML` delegates to it with empty source. |
| `model_test.go` | 1,002 | BuildGraph graph correctness, peer classification, dedup, sorting, port-mutation guard. |
| `render_test.go` | 334 | Placeholder replacement, DTO marshalling, HTML structure assertions. |
| `edge_cases_test.go` | 533 | Empty inputs, WorkloadID without "/", mixed selector/cidr/reserved peers. |

Embedded assets: `assets/` — `cytoscape.min.js`, `dagre.min.js`, `cytoscape-dagre.min.js`. Template: `template.html`.

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add/change node kinds | `model.go` NodeKind constants + `classifyPeer` |
| Change graph construction logic | `BuildGraph` (model.go ~line 183) |
| Change HTML/CSS/JS or embedding | `render.go` + `assets/` + `template.html` |
| Change viz write behavior (atomicity, chmod, skip) | `../common_pipeline.go` `writeVisualizationHTML` (~line 438) |
| Verify determinism | `../common_pipeline_test.go` (HTML byte-for-byte assertions) |

## CONVENTIONS
- Pure + deterministic: `BuildGraph` returns sorted Graph. Nodes sorted by (Kind, ID). Edges by (Source, Target, Direction, Protocol, Port). No `time.Now`, no random IDs.
- Input `[]policy.Policy` is never mutated (test: `TestNoPortMutation` in `model_test.go`).
- Entry point: `writeVisualizationHTML` in `../common_pipeline.go` calls `BuildGraph` + `RenderHTMLWithSource`, writes atomically (temp file + rename), chmod 0644.
- Errors are non-blocking: viz write failure returns error up the pipeline but doesn't abort policy generation.
- Fully offline: all JS is `go:embed`d at build time. No external CDN references.

## ANTI-PATTERNS
- No external CDN references — air-gapped requirement.
- No timestamps, random IDs, or non-deterministic ordering in output.
- Do NOT mutate the input `[]policy.Policy` slice.
- Do NOT put I/O or network access inside `model.go` — it is pure graph construction.
