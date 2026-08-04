# cmd/flowguarder — CLI commands and analysis pipeline

## OVERVIEW
Go CLI entry point: Cobra command tree wired at package level, pipeline orchestration in `common_pipeline.go`.

## STRUCTURE
| File | Lines | Purpose |
|---|---|---|
| `main.go` | 5 | Trivial entry: calls `Execute()` from `root.go`. |
| `root.go` | 52 | Cobra root command, global persistent flags via `rootCmdData`, registers 3 subcommands in `init()`. |
| `analyze.go` | 44 | `flowguarder analyze <path>` — offline file/directory/stdin flow analysis. |
| `live.go` | 294 | `flowguarder live` — streaming from Hubble Relay gRPC or tailing Calico file. |
| `version.go` | 19 | `flowguarder version` — prints version string only (default 1.0.0, ldflags-injectable via -X main.version). |
| `version_test.go` | 45 | Tests: version command prints 1.0.0; rootCmd.Version set. |
| `common_pipeline.go` | 790 | Shared pipeline: `runAnalyzePipeline`, `runLiveCommand`, `ingestDir`, `executeAnalysis`, YAML policy writer (writePolicyYAML/buildNetworkPolicy), JSON/text report printers. |

## WHERE TO LOOK
| Task | File |
|---|---|
| Add a new CLI subcommand | `root.go` (register in `init()`) + new file |
| Modify an existing subcommand's flags | Corresponding `init()` block (`root.go`, `analyze.go`, `live.go`) |
| Add a global persistent flag | `root.go` `init()` → `rootCmd.PersistentFlags()` |
| Change offline analysis pipeline | `common_pipeline.go` (`runAnalyzePipeline`, `ingestDir`) |
| Change live streaming source | `live.go` (`runLiveHubble`, `runLiveCalico`) |
| Modify YAML policy output format | `common_pipeline.go` (`writePolicyYAML`) |
| Modify report output format | `common_pipeline.go` (`printTextReport`, `printJSONReport`) |
| Change version string / output format | `version.go` (var `version` + versionCmd) |

## CONVENTIONS
- All files share `package main`; this directory is the **only** `main` package in the module.
- All Cobra commands are package-level `var` pointers: `rootCmd`, `analyzeCmd`, `liveCmd`, `versionCmd`.
- Subcommand-specific flags are added via `init()` blocks **inside the subcommand file** (not in `root.go`).
- Global persistent flags live in the `rootCmdData` struct (`common_pipeline.go:21`) and are bound via `rootCmd.PersistentFlags().StringVar(&rootFlags.xxx, ...)`.
- Output goes through `cmd.Printf`, `cmd.Println` (Cobra's `*cobra.Command` IO), or `fmt.Fprintln(os.Stderr, ...)`. Never use bare `fmt.Println` for user-facing output.
- Signal-driven cancellation in `live.go`: `signal.NotifyContext` with SIGINT/SIGTERM; all goroutines in live mode respect the context.
- Build-time version injection uses ldflags: `-ldflags "-X main.version=..."`.

## ANTI-PATTERNS
- Do NOT put analysis, parsing, or policy-generation logic here; those belong in `pkg/`.
- Do NOT import `pkg/anomaly` types for direct manipulation; call `anomaly.RunAll()` only.
- Do NOT add Cobra commands outside `init()` in `root.go`; keep command registration in `init()` and command var declarations in their own files.
- Do NOT use bare `fmt.Println` for user-facing output. Use `cmd.Printf/Println` or stderr.
- Do NOT shadow the global `rootFlags` variable from subcommand functions.
