# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-04

## OVERVIEW
flowGuarder is a Go CLI that analyzes Kubernetes network flow logs from Hubble and Calico, detects anomalies, and emits Kubernetes NetworkPolicy / CiliumNetworkPolicy YAML manifests.

## STRUCTURE
```
flowguarder/
├── cmd/flowguarder/   # CLI commands and analysis pipeline
├── pkg/
│   ├── analyze/       # Flow classification, workload aggregation, statistics
│   ├── anomaly/       # Anomaly detectors
│   ├── config/        # YAML config loading
│   ├── flow/          # Canonical Flow data model
│   ├── ingest/        # Input sources (file, dir, stdin, gRPC)
│   ├── parser/        # Flow-log parsers and source auto-detection
│   │   ├── hubble/    # Hubble JSON parser (fail-fast on first parse error)
│   │   ├── goldmane/  # Calico Goldmane gRPC API (FlowResult JSON)
│   │   └── calico/    # Calico JSON parser (log-and-skip bad lines)
│   ├── policy/        # NetworkPolicy / CiliumNetworkPolicy generation
│   └── report/        # Text/JSON report rendering
├── testdata/          # Shared fixture files for parser tests
├── flowlab/           # Demo dataset (hubble-flows*.jsonl) + capture/validate tools
├── dist/              # Krew manifest + Homebrew formula templates
└── .github/workflows/ # CI + release
```

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add a new CLI command | cmd/flowguarder/ |
| Add/modify flow classification | pkg/analyze/classify.go |
| Add/modify anomaly detector | pkg/anomaly/ (implement Detector) |
| Add/modify parser format | pkg/parser/<format>/ |
| Add a new parser format (Calico Goldmane) | pkg/parser/goldmane/ |
| Add live ingestion source | pkg/ingest/ |
| Modify policy output | pkg/policy/ |
| Change config schema | pkg/config/config.go |
| Add/modify report rendering | pkg/report/ |
| Change version string | cmd/flowguarder/version.go |
| Run tests | `make test` |
| Build binary | `make build` |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| Execute | func | cmd/flowguarder/root.go | Cobra root execution |
| runAnalyzePipeline | func | cmd/flowguarder/common_pipeline.go | Offline analysis pipeline |
| runLiveCommand | func | cmd/flowguarder/live.go | Live streaming pipeline |
| Flow | struct | pkg/flow/flow.go | Canonical flow record |
| Parser | interface | pkg/parser/parser.go | Flow parser contract |
| Parser (Goldmane) | struct | pkg/parser/goldmane/parser.go | Streaming JSON parser for Calico Goldmane FlowResult |
| Source | interface | pkg/ingest/ingest.go | Ingestion source contract |
| ClassifyPeer | func | pkg/analyze/classify.go | Traffic peer classification |
| ComputePatterns | func | pkg/analyze/stats.go | Pattern aggregation |
| RunAll | func | pkg/anomaly/detect.go | Detector orchestration |
| Detector | interface | pkg/anomaly/anomaly.go | Anomaly detector contract |
| Build | func | pkg/policy/builder.go | Abstract policy model |
| BuildCilium | func | pkg/policy/cilium.go | CiliumNetworkPolicy render |
| Load | func | pkg/config/config.go | Config loading |

## CONVENTIONS
- Table-driven tests with `t.Parallel()` everywhere.
- `var _ Interface = (*Impl)(nil)` compile-time interface checks.
- Parsers register via `init()` into `parserRegistry`.
- Deterministic output: sort keys/slices before returning.
- Custom errors carry source: `parser.FormatError{Source, Message}`.
- Calico parser logs-and-skips bad lines; Hubble parser fail-fast on first parse error.
- Output writers target `io.Writer`; report package uses flat transfer structs.

## ANTI-PATTERNS (THIS PROJECT)
- Do not add randomness or I/O inside anomaly detectors; they must be pure.
- Do not mutate input flow slices in analysis functions (return new slices).
- Do not rely on external cluster access for offline analysis.
- Do not output non-deterministic maps without sorting.
- Do not couple CLI logic into pkg/ packages.

## UNIQUE STYLES
- Source auto-detection probes first 4096 bytes for `"verdict"` (Hubble), `"action"` (Calico), or syslog priority prefix.
- Goldmane format is proto3 JSON encoding (camelCase field names, int64 fields as strings); auto-detect probes for both "flow" and "sourceName" in the first 4096 bytes.
- Goldmane parser populates both `Flow.Source.Labels`/`Flow.Destination.Labels` and the top-level `SourceLabels`/`DestLabels` shortcut fields, mirroring Hubble behaviour.
- Endpoint labels are derived from `flow.sourceLabels`/`flow.destLabels` so `analyze.ResolveWorkload` can resolve workload names by label priority.
- Workload IDs are always `"namespace/name"`.
- Policy generation is two-phase: abstract `Policy` model first, then vendor-specific renderer.

## COMMANDS
```bash
make build    # build bin/flowguarder
make test     # go test ./...
make vet      # go vet ./...
make lint     # golangci-lint run ./... (skips if not installed)
make clean    # rm -rf bin/
goreleaser build --single-target
goreleaser release --snapshot
# Release workflow (.github/workflows/release.yml): tag v* push → goreleaser-action v7 (draft release)
```

## NOTES
- gopls is not installed in this environment; rely on grep/read/glob for navigation.
- `.omo/` is untracked + gitignored internal orchestration state (boulder plans/notepads).
- CI uses Go 1.25 (setup-go@v5), matching go.mod 1.25.0.
- `pkg/analyze/analyze.go` and `pkg/report/report.go` are intentionally near-empty package declarations.
