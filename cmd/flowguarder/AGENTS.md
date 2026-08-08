# cmd/flowguarder — CLI commands and analysis pipeline

## OVERVIEW
Go CLI entry point: Cobra command tree wired at package level, pipeline orchestration in `common_pipeline.go`. One of only three main packages in the module (others: `flowlab/dump-hubble`, `flowlab/validate-hubble`).

## STRUCTURE
| File | Lines | Purpose |
|---|---|---|
| `main.go` | 5 | Trivial entry: calls `Execute()` from `root.go`. |
| `root.go` | 52 | Cobra root command, global persistent flags via `rootCmdData`, registers 3 subcommands in `init()`. |
| `analyze.go` | 44 | `flowguarder analyze <path>` — offline file/directory/stdin flow analysis. |
| `live.go` | 311 | `flowguarder live` — streaming from Hubble Relay gRPC or tailing Calico file. |
| `version.go` | 19 | `flowguarder version` — prints version string only (default 1.1.0, ldflags-injectable via -X main.version). |
| `version_test.go` | 45 | Tests: version command prints 1.1.0; rootCmd.Version set. |
| `common_pipeline.go` | 992 | Shared pipeline: `runAnalyzePipeline`, `runLiveCommand`, `ingestDir`, `executeAnalysis`, YAML policy writer (`writePolicyYAML`/`buildNetworkPolicy`), **`writeCiliumYAML` (CLI-side CiliumNetworkPolicy writer used by BOTH analyze and live pipelines)**, JSON/text report printers. |
| `common_pipeline_test.go` | 1900 | Pipeline regression tests (offline analyze, policy writing, reports). |
| `live_test.go` | 247 | Live pipeline tests. |
| `review5_test.go` | 393 | **FROZEN review gate — DO NOT MODIFY**; asserts REVIEW5 acceptance criteria incl. NetPol CIDR twins. |
| `review6_test.go` | 206 | **FROZEN review gate — DO NOT MODIFY**; asserts REVIEW6 acceptance criteria. |

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

## CONVENTIONS
- All files share `package main`; this directory is **one of only three** `main` packages in the module (others: `flowlab/dump-hubble`, `flowlab/validate-hubble`).
- All Cobra commands are package-level `var` pointers: `rootCmd`, `analyzeCmd`, `liveCmd`, `versionCmd`.
- Subcommand-specific flags are added via `init()` blocks **inside the subcommand file** (not in `root.go`).
- Global persistent flags live in the `rootCmdData` struct (`common_pipeline.go:21`) and are bound via `rootCmd.PersistentFlags().StringVar(&rootFlags.xxx, ...)`.
- Output goes through `cmd.Printf`, `cmd.Println` (Cobra's `*cobra.Command` IO), or `fmt.Fprintln(os.Stderr, ...)`. Never use bare `fmt.Println` for user-facing output.
- Signal-driven cancellation in `live.go`: `signal.NotifyContext` with SIGINT/SIGTERM; all goroutines in live mode respect the context.
- Build-time version injection uses ldflags: `-ldflags "-X main.version=..."`.
- `writeCiliumYAML` (common_pipeline.go) is the **single** CLI-side CNP writer; both `analyze` and `live` pipelines route Cilium output through it — never write CNP YAML inline in either command.
- `parseWorkloadSelectorV2` (common_pipeline.go ~line 468) reads NetPol CIDR twins and is **frozen** — do not modify its semantics.
- The CLI reads `apiserver_workload_selector` from config (default `kube-system/kube-apiserver`); `isWorldPeer` keeps plain pub/pvt peers on 9443/8443/5443/6443 as `world` instead of `apiserver`.
- The CLI recognizes `"world"` and `"entity:world"` peers via `isWorldPeer` so world egress maps to Cilium entity sentinels.

## ANTI-PATTERNS
- Do NOT put analysis, parsing, or policy-generation logic here; those belong in `pkg/`.
- Do NOT import `pkg/anomaly` types for direct manipulation; call `anomaly.RunAll()` only.
- Do NOT add Cobra commands outside `init()` in `root.go`; keep command registration in `init()` and command var declarations in their own files.
- Do NOT use bare `fmt.Println` for user-facing output. Use `cmd.Printf/Println` or stderr.
- Do NOT shadow the global `rootFlags` variable from subcommand functions.
- Do NOT remove or alter the NetPol CIDR twins — the frozen review gates (`review5_test.go`, `review6_test.go`) assert them.
- Do NOT modify `review5_test.go` / `review6_test.go` — they are frozen acceptance locks.
