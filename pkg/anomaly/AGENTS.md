# `pkg/anomaly/` — Anomaly Detectors

## OVERVIEW
7 pure-function detectors scan flows for policy violations; `RunAll` orchestrates and deduplicates.

## WHERE TO LOOK
| Task | File |
|---|---|
| Add a new detector | `rare.go` (template) → register in `detect.go` `RunAll` slice |
| Run all detectors | `detect.go` — `RunAll()` |
| Change anomaly ID format | `anomaly.go` — `NewAnomaly()` hashes `type|workload|description` with SHA-256, takes first 16 hex chars |
| Change severity sort order | `detect.go` — `sortAnomalies()` severity map and `sort.Slice` comparator |
| Modify flow dropped detection | `dropped.go` |
| Modify cross-namespace detection | `namespace.go` |
| Modify port-scan detection | `portscan.go` (threshold from `cfg.PortScanThreshold`, window from `cfg.PortScanWindowSeconds`) |
| Modify public egress detection | `egress.go` (allowlist CIDRs + `KnownGoodExternalEndpoints`) |
| Modify TLS/unknown domain detection | `tls.go` (compares L7 SNI/Host against allowlist) |
| Modify asymmetric traffic detection | `asymmetric.go` (skips CronJob workloads, default ratio 10:1) |

## CONVENTIONS
- Every detector is a zero-valued struct with a `Detect(flows, patterns, workloads, cfg) []Anomaly` method.
- `Detector` interface: `Detect([]flow.Flow, []Pattern, analyze.Workloads, config.Config) []Anomaly`.
- `Pattern` is a type alias: `type Pattern = analyze.Pattern`.
- Compile-time interface check at bottom of every detector file: `var _ Detector = (*XxxDetector)(nil)`.
- `Anomaly.ID` is `sha256(type|workload|description)[:16]` hex — deterministic given identical inputs.
- `RunAll` hardcodes the detector slice in a fixed order; appending without updating `RunAll` breaks discoverability and test coverage.
- Detectors are pure functions: no randomness, no time.Now(), no I/O. All thresholds come from `cfg`.
- Output is deterministically sorted: severity (high→medium→low→info), then workload, then type.

## ANTI-PATTERNS
- Do NOT add randomness or `time.Now()` inside detectors — use `cfg` values instead.
- Do NOT mutate `flows`, `patterns`, or `workloads` arguments (return new slices/maps).
- Do NOT skip the `var _ Detector = ...` compile-time check.
- Do NOT register a detector dynamically — it must be a named type added to `RunAll`'s slice.
- Do NOT call out to network, filesystem, or cluster APIs from any detector.
- Do NOT change the `RunAll` detector order without updating tests that depend on deterministic output ordering.
- Do NOT use package-level mutable globals to pass data into detectors — pass via `Detect(flows, ...)` arguments.
  This is the root cause of the port-scan no-op (see Known Issues below).

## KNOWN ISSUES
- **Port-scan detector is a silent no-op (dormant bug)** — `pkg/anomaly/portscan.go` declares a package-global
  `flowFlows` slice at line 82 (`var flowFlows = func() []flow.Flow { return nil }()`) with comment
  "will be set via RunAll", but nothing ever assigns it. `Detect` iterates `flowFlows` (line 37), so it always
  sees zero flows and never fires. `RunAll` in `detect.go` receives the `flows` parameter but never wires it into
  the port-scan detector. Result: the `port-scan` anomaly is a permanent no-op. Do NOT rely on it until fixed.
  Fix direction: wire the flows through `RunAll` (it already receives the slice) and remove the package-level
  global so port-scan uses the same `Detect(flows, ...)` signature as all other detectors.
