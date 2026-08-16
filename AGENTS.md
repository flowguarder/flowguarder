# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-04 (refreshed 2026-08-16, updated 2026-08-16)

## OVERVIEW
flowGuarder is a Go CLI that analyzes Kubernetes network flow logs from Hubble and Calico, detects anomalies, and emits Kubernetes NetworkPolicy / CiliumNetworkPolicy YAML manifests.

## STRUCTURE
```
flowguarder/
├── cmd/flowguarder/   # CLI commands and analysis pipeline (~1195 LOC)
│   ├── reports.go     # Report type validation (validateReports, 14 LOC)
│   ├── tui/           # Interactive TUI for simulate (Bubble Tea, ~1100 LOC)
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
│   ├── config/        # YAML config loading & schema validation (config.go 492 LOC + config_test.go 1099 LOC)
│   ├── flow/          # Canonical Flow data model + label helpers
│   ├── ingest/        # Input sources (file, dir, stdin, gRPC)
│   ├── parser/        # Flow-log parsers + source auto-detection
│   │   ├── hubble/    # Hubble JSON parser (fail-fast on first parse error)
│   │   ├── goldmane/  # Calico Goldmane gRPC API (FlowResult proto3 JSON)
│   │   └── calico/    # Calico JSON parser (log-and-skip bad lines)
│   ├── policy/        # Abstract model + vendor renderers
│   │   ├── builder.go # Abstract policy model + dual-carry: CIDR twins + entity sentinels
	│   │   ├── cilium.go # CiliumNetworkPolicy renderer (677 LOC)
│   │   ├── builder_test.go # 3624 LOC
│   │   └── cilium_test.go # 1313 LOC
│   ├── report/        # Text/JSON report rendering + report data structs
│   └── simulate/      # Traffic simulation against policy manifests (loader.go, eval_np.go, eval_cnp.go, types.go + tests)
├── testdata/          # Shared fixture files for parser tests
├── flowlab/           # Demo dataset (hubble-flows-before.jsonl, 17MB; tracked in git since 334abec) — Dockerfile, kind-config.yaml, demo-pods.yaml, docker-run.sh, entrypoint.sh; dump-hubble/main.go, validate-hubble/main.go (ONLY other main packages in module); flowlab-shared/ (empty)
├── cmd/flowguarder/visualize/  # Policy graph visualization: BuildGraph (model.go, 410 LOC) + RenderHTMLWithSource (render.go, 254 LOC, inlined Cytoscape.js, no CDN)
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
| Add/modify simulate logic | pkg/simulate/ |
| Modify simulate CLI | cmd/flowguarder/simulate.go |
| Modify TUI layout/navigation | cmd/flowguarder/tui/ (model.go View/Update, inputs.go focus) |
| Modify TUI object extraction | cmd/flowguarder/tui/extract.go |
| Add/modify report rendering | pkg/report/ |
| Change version string | cmd/flowguarder/version.go |
| Run tests | `make test` |
| Build binary | `make build` |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| Execute | func | cmd/flowguarder/root.go | Cobra root execution |
| runAnalyzePipeline | func | cmd/flowguarder/common_pipeline.go (~1195 LOC) | Offline analysis pipeline |
| writeVisualizationHTML | func | cmd/flowguarder/common_pipeline.go (~438) | CLI-side viz writer used by both analyze and live pipelines; atomic temp-file+rename |
| runLiveCommand | func | cmd/flowguarder/live.go (326 LOC) | Live streaming pipeline |
| Flow | struct | pkg/flow/flow.go | Canonical flow record |
| Parser | interface | pkg/parser/parser.go | Flow parser contract |
| Parser (Goldmane) | struct | pkg/parser/goldmane/parser.go | Streaming JSON parser for Calico Goldmane FlowResult |
| Source | interface | pkg/ingest/ingest.go | Ingestion source contract |
| ClassifyPeer | func | pkg/analyze/classify.go | Traffic peer classification |
| ComputePatterns | func | pkg/analyze/stats.go | Pattern aggregation |
| RunAll | func | pkg/anomaly/detect.go | Detector orchestration, fixed order |
| Detector | interface | pkg/anomaly/anomaly.go | Anomaly detector contract |
| Build | func | pkg/policy/builder.go (1377 LOC) | Abstract policy model with dual-carry CIDR twins + entity sentinels |
| BuildCilium | func | pkg/policy/cilium.go (677 LOC) | CiliumNetworkPolicy render of entity form (skips CIDR twins) |
| BuildGraph | func | cmd/flowguarder/visualize/model.go (~183) | Builds abstract graph (Node/Edge/Graph) from []policy.Policy; pure + sorted |
| RenderHTMLWithSource | func | cmd/flowguarder/visualize/render.go | Self-contained offline HTML (inlined Cytoscape.js + dagre, no CDN) |
| writeCiliumYAML | func | cmd/flowguarder/common_pipeline.go | CLI-side CNP writer, used by both analyze and live pipelines |
| resolveEntitySet | func | pkg/policy/cilium.go (549-582) | Computes entity sets; host↔remote-node closure |
| parseWorkloadSelectorV2 | func | cmd/flowguarder/common_pipeline.go (line 658) | Reads NetPol CIDR twins, frozen |
| Load | func | pkg/config/config.go | Config loading |
| validateReports | func | cmd/flowguarder/reports.go | Report type validation |
| common_pipeline_test | file | cmd/flowguarder/common_pipeline_test.go (2851 LOC) | Pipeline regression tests |
| review5_test | file | cmd/flowguarder/review5_test.go (393 LOC) | Frozen review gate - DO NOT MODIFY |
| review6_test | file | cmd/flowguarder/review6_test.go (206 LOC) | Frozen review gate - DO NOT MODIFY |
| LoadPolicies | func | pkg/simulate/loader.go | Recursive YAML loader, multi-doc split, NP/CNP kind auto-detect |
| EvaluateNetworkPolicy | func | pkg/simulate/eval_np.go | NP verdict: allow/deny/undetermined for L4 + selectors + ipBlock |
| EvaluateCiliumNetworkPolicy | func | pkg/simulate/eval_cnp.go | CNP verdict incl. entities, toFQDNs, DNS L7 (port 53) |

## CONVENTIONS
- Table-driven tests with `t.Parallel()` everywhere.
- `var _ Interface = (*Impl)(nil)` compile-time interface checks.
- Parsers register via `init()` into `parserRegistry`.
- Deterministic output: sort keys/slices before returning.
- Custom errors carry source: `parser.FormatError{Source, Message}`.
- Calico parser logs-and-skips bad lines; Hubble parser fail-fast on first parse error.
- Output writers target `io.Writer`; report package uses flat transfer structs.
- Simulate evaluators are pure: take pre-loaded []LoadedPolicy, never do I/O; output deterministic (sorted MatchingFiles).

## ANTI-PATTERNS (THIS PROJECT)
- Do not add randomness or I/O inside anomaly detectors; they must be pure.
- Do not mutate input flow slices in analysis functions (return new slices).
- Do not rely on external cluster access for offline analysis.
- Do not output non-deterministic maps without sorting.
- Do not couple CLI logic into pkg/ packages.
- Do NOT remove the NetPol CIDR twins — the frozen review gates (cmd/flowguarder/review5_test.go, review6_test.go) assert them.

## UNIQUE STYLES
- Source auto-detection probes first 4096 bytes for `"verdict"` (Hubble), `"action"` (Calico), or syslog priority prefix.
- Goldmane is proto3 JSON (camelCase field names, int64 fields as strings); auto-detect probes for both "flow" and "sourceName" in first 4096 bytes; parser populates `Flow.Source.Labels`/`Flow.Destination.Labels` plus top-level `SourceLabels`/`DestLabels` shortcuts, mirroring Hubble.
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
# Simulate traffic against policies: flowguarder simulate --policies ./policies --src default/frontend --dst default/backend --port 8080
goreleaser build --single-target
goreleaser release --snapshot
# Release (.github/workflows/release.yml): tag v* push → goreleaser-action v7 (draft release)
```

## NOTES
- gopls is available (LSP); for quick navigation grep/read/glob still work well.
- `.omo/` is untracked + gitignored internal orchestration state (boulder plans/notepads).
- CI uses Go 1.25 (setup-go@v5), matching go.mod 1.25.0.
- `pkg/analyze/analyze.go` and `pkg/report/report.go` are intentionally near-empty package declarations.
- `policies2/` was removed in commit de4b49e ("output removal"). `policies-calico/`, `policies-hubble/`, `policies-hubble-cilium/` are untracked review artifacts.
- New config keys: `apiserver_workload_selector` (struct: ns+name, defaults to kube-system/kube-apiserver when present) + `node_cidrs` (optional IP ranges); NetworkPolicy renders node /32 + node_cidrs, never service-range `10.96.0.0/12`.
- Port-scan detector (`pkg/anomaly/portscan.go`) has a known dormant bug: its global `flowFlows` slice is never wired (declared nil-initialized at portscan.go:82, never assigned anywhere) — the detector is effectively a silent no-op; do not rely on it until wired.
- Current version 1.3.1; rootCmd.Version references the version var (root.go:16 `Version: version`) so `--version` and `flowguarder version` stay consistent, including under goreleaser ldflags injection.
