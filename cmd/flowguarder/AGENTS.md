# cmd/flowguarder — CLI commands and analysis pipeline

## OVERVIEW
Go CLI entry point: Cobra command tree wired at package level, pipeline orchestration in `common_pipeline.go`. One of only three main packages in the module (others: `flowlab/dump-hubble`, `flowlab/validate-hubble`).

## STRUCTURE
| File | Lines | Purpose |
|---|---|---|
| `main.go` | 5 | Trivial entry: calls `Execute()` from `root.go`. |
| `root.go` | 61 | Cobra root command, global persistent flags via `rootCmdData`, registers 3 subcommands in `init()`. Includes `--skip-visualize` persistent flag (line 50) and `Version: version` (line 16). |
| `analyze.go` | 44 | `flowguarder analyze <path>` — offline file/directory/stdin flow analysis. |
| `live.go` | 326 | `flowguarder live` — streaming from Hubble Relay gRPC or tailing Calico file. |
| `version.go` | 22 | `flowguarder version` — prints version string only (default 1.4.0, ldflags-injectable via -X main.version). References `version` var (root.go:16) so `--version` and `flowguarder version` are always consistent. |
| `version_test.go` | 45 | Tests: version command prints 1.4.0; rootCmd.Version == "1.4.0" — hardcodes "1.4.0" in TWO places. |
| `reports.go` | 14 | Report type validation: `validateReports()` — single small helper, rejects unknown report names. |
| `common_pipeline.go` | 1195 | Shared pipeline: `runAnalyzePipeline` (~92), `runLiveCommand`, `ingestDir`, `executeAnalysis`, YAML policy writer (`writePolicyYAML`/`buildNetworkPolicy`), **`writeCiliumYAML` (~422, CLI-side CiliumNetworkPolicy writer used by BOTH analyze and live pipelines)**, `writeVisualizationHTML` (~438, atomic temp-file+rename), `printTextReport` (~1071), JSON/text report printers. |
| `common_pipeline_test.go` | 2851 | Pipeline regression tests (offline analyze, policy writing, reports). |
| `live_test.go` | 344 | Live pipeline tests. |
| `review5_test.go` | 393 | **FROZEN review gate — DO NOT MODIFY**; asserts REVIEW5 acceptance criteria incl. NetPol CIDR twins. |
| `review6_test.go` | 206 | **FROZEN review gate — DO NOT MODIFY**; asserts REVIEW6 acceptance criteria. |
| `visualize/model.go` | 410 | Graph model: `BuildGraph` (deterministic graph from `[]policy.Policy`, node kinds: namespace/workload/reserved/cidr/selector). |
| `visualize/render.go` | 254 | `RenderHTMLWithSource` (renders HTML with inlined Cytoscape.js + dagre, no CDN, embedded assets). |
| `visualize/template.html` | 780 | HTML template with placeholder tokens replaced by `render.go`. |
| `visualize/model_test.go` | 1002 | Graph model tests. |
| `visualize/render_test.go` | 334 | Render tests. |
| `visualize/edge_cases_test.go` | 533 | Edge-case tests. |
| `simulate.go` | 183 | `flowguarder simulate` — Cobra command + `simFlags` struct; resolves endpoints, loads policies, runs `combineVerdicts`, delegates output. |
| `simulate_validation.go` | 183 | Verdict logic: `buildEndpoint` constructs `Endpoint` from flags; `combineVerdicts` priority allow > deny > undetermined; OR-combines NP+CNP results; `parseLabelString` helper. |
| `simulate_output.go` | 109 | Print formatting: `printText` / `printJSON` verdict output. |
| `simulate_test.go` | 153 | 10 integration tests for simulate verdict logic and flag combinations. |
| `tui/model.go` | 435 | Core TUI model, View/Update, evaluation logic, verdict helpers. |
| `tui/inputs.go` | 166 | Focus constants, text input initialization, input rendering. |
| `tui/lists.go` | 110 | Styled list creation, selectable item builders. |
| `tui/result.go` | 68 | Verdict/error display pane. |
| `tui/extract.go` | 203 | `ExtractSelectableObjects()` — workload/entity/CIDR extraction from policies. |
| `tui/extract_test.go` | 380 | 10 extraction tests. |
| `tui/model_test.go` | 97 | 7 tests: Init, window resize, quit, view. |
| `tui/stub.go` | 10 | Blank Charmbracelet imports (keeps go.mod deps alive). |
| `tui_smoke_test.go` | 62 | 5 flag-parsing smoke tests (in parent package). |

## WHERE TO LOOK
| Task | File |
|---|---|
| Add a new CLI subcommand | `root.go` (register in `init()`) + new file |
| Modify an existing subcommand's flags | Corresponding `init()` block (`root.go`, `analyze.go`, `live.go`) |
| Add a global persistent flag | `root.go` `init()` → `rootCmd.PersistentFlags()` |
| Change offline analysis pipeline | `common_pipeline.go` (`runAnalyzePipeline`, `ingestDir`) |
| Change live streaming source | `live.go` (`runLiveHubble`, `runLiveCalico`) |
| Modify YAML policy output format | `common_pipeline.go` (`writePolicyYAML`) |
| Modify CiliumNetworkPolicy YAML output | `common_pipeline.go` (`writeCiliumYAML`) — used by both analyze and live; renders entity form from `pkg/policy` |
| Modify report output format | `common_pipeline.go` (`printTextReport`, `printJSONReport`) |
| Change version string / output format | `version.go` (var `version` + versionCmd) |
| Validate report type flags | `reports.go` (`validateReports`) |
| Modify simulate verdict logic | `simulate_validation.go` (`combineVerdicts`: allow > deny > undetermined, OR-combines NP+CNP) |
| Modify TUI layout/navigation | `tui/model.go` (View/Update), `tui/inputs.go` (focus constants) |
| Modify TUI object extraction | `tui/extract.go` (`ExtractSelectableObjects`) |
| Modify visualization graph model | `visualize/model.go` (`BuildGraph`, node kinds) |
| Modify visualization HTML output | `visualize/render.go` + `common_pipeline.go` (`writeVisualizationHTML`) |

## CONVENTIONS
- All files share `package main`; this directory is **one of only three** `main` packages in the module (others: `flowlab/dump-hubble`, `flowlab/validate-hubble`).
- All Cobra commands are package-level `var` pointers: `rootCmd`, `analyzeCmd`, `liveCmd`, `versionCmd`.
- Subcommand-specific flags are added via `init()` blocks **inside the subcommand file** (not in `root.go`).
- Global persistent flags live in the `rootCmdData` struct (`common_pipeline.go:37`) and are bound via `rootCmd.PersistentFlags().StringVar(&rootFlags.xxx, ...)`.
- Output goes through `cmd.Printf`, `cmd.Println` (Cobra's `*cobra.Command` IO), or `fmt.Fprintln(os.Stderr, ...)`. Never use bare `fmt.Println` for user-facing output.
- Signal-driven cancellation in `live.go`: `signal.NotifyContext` with SIGINT/SIGTERM; all goroutines in live mode respect the context.
- Build-time version injection uses ldflags: `-ldflags "-X main.version=..."`.
- **Every version bump MUST update `version.go` (default string) AND `version_test.go` (hardcoded "1.4.0" assertions in TWO places).** The `Version: version` reference in `root.go` is automatic — both `--version` and `flowguarder version` stay consistent.
- `writeCiliumYAML` (common_pipeline.go ~422) is the **single** CLI-side CNP writer; both `analyze` and `live` pipelines route Cilium output through it — never write CNP YAML inline in either command.
- `writeVisualizationHTML` (common_pipeline.go ~438): atomic temp-file+rename, non-blocking on errors, `chmod 0644` (#nosec G302). Output must be deterministic (byte-identical across runs — no timestamps, no random IDs) and fully offline (inlined JS, no CDN).
- `parseWorkloadSelectorV2` (common_pipeline.go ~line 658) reads NetPol CIDR twins and is **frozen** — do not modify its semantics.
- The CLI reads `apiserver_workload_selector` from config (default `kube-system/kube-apiserver`); `isWorldPeer` keeps plain pub/pvt peers on 9443/8443/5443/6443 as `world` instead of `apiserver`.
- The CLI recognizes `"world"` and `"entity:world"` peers via `isWorldPeer` so world egress maps to Cilium entity sentinels.

## ANTI-PATTERNS
- Do NOT put analysis, parsing, or policy-generation logic here; those belong in `pkg/`.
- Do NOT import `pkg/anomaly` types for direct manipulation; call `anomaly.RunAll()` only.
- Do NOT add Cobra commands outside `init()` in `root.go`; keep command registration in `init()` and command var declarations in their own files.
- Do NOT use bare `fmt.Println` for user-facing output. Use `cmd.Printf/Println` or stderr.
- Do NOT shadow the global `rootFlags` variable from subcommand functions.
- Do NOT run `simulate_test.go` tests with `t.Parallel()` — shared rootCmd/simFlags globals; the file uses a global snapshot/restore pattern instead.
- Do NOT remove or alter the NetPol CIDR twins — the frozen review gates (`review5_test.go`, `review6_test.go`) assert them.
- Do NOT modify `review5_test.go` / `review6_test.go` — they are frozen acceptance locks.
- Do NOT put I/O or file access in the TUI package — policies are loaded by the CLI layer and passed in.
- Do NOT use pointer receiver methods on tui.Model where value receivers work — tea.Model requires value semantics.
