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
| `version.go` | 22 | `flowguarder version` — prints version string only (default 1.4.1, ldflags-injectable via -X main.version). References `version` var (root.go:16) so `--version` and `flowguarder version` are always consistent. |
| `version_test.go` | 45 | Tests: version command prints 1.4.1; rootCmd.Version == "1.4.1" — hardcodes "1.4.1" in TWO places. |
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
| `tui/` | ~8016 | Unified 3-tab Bubble Tea TUI (Analyze/Live/Simulate) — **see `tui/AGENTS.md`** for the full per-file map, navigation, and golden-test contract. |
| `tui_runners.go` | 135 | Glue between TUI and pipelines: `tuiAnalyzeRunner`, `tuiLiveRunner` (build cobra commands, capture output into buffer, route `pkg/policy` logs away from TUI frames), `tuiPolicyLoader`; wired via `NewUnifiedOpts()`. |
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
| Modify TUI (any aspect) | `tui/` — start from `tui/AGENTS.md` (navigation map, form fields, goldens) |
| Wire a new TUI runner / change runner signatures | `tui_runners.go` + `tui/model.go` (`AnalyzeRunner`/`LiveRunner` types) |
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
- **Every version bump MUST update `version.go` (default string) AND `version_test.go` (hardcoded "1.4.1" assertions in TWO places).** The `Version: version` reference in `root.go` is automatic — both `--version` and `flowguarder version` stay consistent.
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
