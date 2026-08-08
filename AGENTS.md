# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-04 (refreshed 2026-08-07)

## OVERVIEW
flowGuarder is a Go CLI that analyzes Kubernetes network flow logs from Hubble and Calico, detects anomalies, and emits Kubernetes NetworkPolicy / CiliumNetworkPolicy YAML manifests.

## STRUCTURE
```
flowguarder/
├── cmd/flowguarder/   # CLI commands and analysis pipeline (~790-992 LOC)
├── pkg/
│   ├── analyze/       # Flow classification, workload aggregation, statistics
│   │   ├── classify.go
│   │   ├── stats.go
│   │   └── workload.go
│   ├── anomaly/       # Anomaly detectors (287 LOC, 7 detectors + orchestrator)
│   │   ├── detect.go  # RunAll orchestrator; fixed detector order
│   │   ├── portscan.go
│   │   ├── asym.go
│   │   ├── ns.go
│   │   ├── tls.go
│   │   ├── drop.go
│   │   ├── rare.go
│   │   └── egw.go
│   ├── config/        # YAML config loading & schema validation
│   │   ├── config.go
│   │   └── schema.go
│   ├── flow/          # Canonical Flow data model + label helpers
│   ├── ingest/        # Input sources (file, dir, stdin, gRPC)
│   ├── parser/        # Flow-log parsers + source auto-detection
│   │   ├── hubble/    # Hubble JSON parser (fail-fast on first parse error)
│   │   ├── goldmane/  # Calico Goldmane gRPC API (FlowResult proto3 JSON)
│   │   └── calico/    # Calico JSON parser (log-and-skip bad lines)
│   ├── policy/        # Abstract model + vendor renderers (~712-2746 LOC)
│   │   ├── builder.go # Abstract policy model + dual-carry: CIDR twins + entity sentinels
│   │   ├── cilium.go # CiliumNetworkPolicy renderer (~712 LOC)
│   │   ├── builder_test.go # ~2746 LOC
│   │   └── cilium_test.go # ~1130 LOC
│   └── report/        # Text/JSON report rendering + report data structs
├── testdata/          # Shared fixture files for parser tests
├── flowlab/           # Demo dataset (hubble-flows-before.jsonl, 17MB fixture) + capture/validate tools
│   ├── Dockerfile, kind-config.yaml, demo-pods.yaml, docker-run.sh, entrypoint.sh
│   ├── dump-hubble/main.go, validate-hubble/main.go (ONLY other main packages in module)
│   └── flowlab-shared/  # Empty directory
├── policies-calico/   # generated Calico policy artifacts (untracked)
├── policies-hubble/   # generated Hubble policy artifacts (untracked)
├── policies-hubble-cilium/  # generated Hubble+Cilium policy artifacts (untracked)
├── .codegraph/        # codegraph index dir (codegraph.db ~4.5MB)
├── dist/              # Krew manifest + Homebrew formula templates (gitignored except !dist/flowguarder.rb, !dist/flowguarder.yaml)
├── REVIEW5.md…REVIEW9.md  # Review evidence docs (untracked)
├── tenant1-calico-flows.jsonl  # gitignored fixture
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
| runAnalyzePipeline | func | cmd/flowguarder/common_pipeline.go (~992 LOC) | Offline analysis pipeline |
| runLiveCommand | func | cmd/flowguarder/live.go (~311 LOC) | Live streaming pipeline |
| Flow | struct | pkg/flow/flow.go | Canonical flow record |
| Parser | interface | pkg/parser/parser.go | Flow parser contract |
| Parser (Goldmane) | struct | pkg/parser/goldmane/parser.go | Streaming JSON parser for Calico Goldmane FlowResult |
| Source | interface | pkg/ingest/ingest.go | Ingestion source contract |
| ClassifyPeer | func | pkg/analyze/classify.go | Traffic peer classification |
| ComputePatterns | func | pkg/analyze/stats.go | Pattern aggregation |
| RunAll | func | pkg/anomaly/detect.go | Detector orchestration, fixed order |
| Detector | interface | pkg/anomaly/anomaly.go | Anomaly detector contract |
| Build | func | pkg/policy/builder.go (~1157 LOC) | Abstract policy model with dual-carry CIDR twins + entity sentinels |
| BuildCilium | func | pkg/policy/cilium.go (~712 LOC) | CiliumNetworkPolicy render of entity form (skips CIDR twins) |
| writeCiliumYAML | func | cmd/flowguarder/common_pipeline.go | CLI-side CNP writer, used by both analyze and live pipelines |
| resolveEntitySet | func | pkg/policy/cilium.go (~lines 543-579) | Computes entity sets; host↔remote-node closure |
| parseWorkloadSelectorV2 | func | cmd/flowguarder/common_pipeline.go (~line 468) | Reads NetPol CIDR twins, frozen |
| Load | func | pkg/config/config.go | Config loading |
| common_pipeline_test | file | cmd/flowguarder/common_pipeline_test.go (1900 LOC) | Pipeline regression tests |
| review5_test | file | cmd/flowguarder/review5_test.go (393 LOC) | Frozen review gate - DO NOT MODIFY |
| review6_test | file | cmd/flowguarder/review6_test.go (206 LOC) | Frozen review gate - DO NOT MODIFY |

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
- Do NOT remove the NetPol CIDR twins — the frozen review gates (cmd/flowguarder/review5_test.go, review6_test.go) assert them.

## UNIQUE STYLES
- Source auto-detection probes first 4096 bytes for `"verdict"` (Hubble), `"action"` (Calico), or syslog priority prefix.
- Goldmane format is proto3 JSON encoding (camelCase field names, int64 fields as strings); auto-detect probes for both "flow" and "sourceName" in the first 4096 bytes.
- Goldmane parser populates both `Flow.Source.Labels`/`Flow.Destination.Labels` and the top-level `SourceLabels`/`DestLabels` shortcut fields, mirroring Hubble behaviour.
- Endpoint labels are derived from `flow.sourceLabels`/`flow.destLabels` so `analyze.ResolveWorkload` can resolve workload names by label priority.
- Workload IDs are always `"namespace/name"`.
- Policy generation is two-phase: abstract `Policy` model first, then vendor-specific renderer. Cilium rendering emits entity sentinels (fromEntities/toEntities) for reserved peers instead of in-cluster CIDRs; NetPol CIDR twins are kept for NetworkPolicy compatibility and skipped by the Cilium renderer.
- Apiserver-port override (review9) fires ONLY for `isKubeAPIServerPeer`: reserved `kube-apiserver` label OR `apiserver_workload_selector` match, defaulting to `kube-system/kube-apiserver`. Plain `pub`, `pvt`, `world` peers on 9443/8443/5443/6443 stay `world`.

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
- `policies2/` was removed in commit de4b49e ("output removal"). `policies-calico/`, `policies-hubble/`, `policies-hubble-cilium/` are untracked review artifacts.
- New config keys: `apiserver_workload_selector` (struct: namespace+name, defaults to kube-system/kube-apiserver when present in flows) and `node_cidrs` (optional IP ranges for NetworkPolicy node rule rendering). NetworkPolicy renders node /32 IPs + optional node_cidrs, never service-range `10.96.0.0/12`.
- Port-scan detector (`pkg/anomaly/portscan.go`) has a known dormant bug: its global `flowFlows` slice is never wired (declared nil-initialized at portscan.go:82, never assigned anywhere) — the detector is effectively a silent no-op; do not rely on it until wired.
