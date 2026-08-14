# FLOWLAB SUBDIRECTORY KNOWLEDGE BASE

## OVERVIEW
`flowlab/` is the demo environment and tooling for flowGuarder: a kind-cluster setup that captures real Hubble flow logs and validates them, plus the canonical demo dataset used by the project's README quick-start and review-gate tests. It contains two `main` packages that are the only other entrypoints in the module besides `cmd/flowguarder`.

## STRUCTURE
| Entry | Type/Purpose |
|---|---|
| `hubble-flows-before.jsonl` | 17MB / ~12,178-line Hubble flow fixture — the canonical demo dataset |
| `dump-hubble/main.go` | Captures live Hubble flows via Hubble Relay gRPC; streams proto3 JSON to stdout |
| `validate-hubble/main.go` | Parses a Hubble JSONL file through the real `pkg/parser/hubble` and reports valid/invalid counts |
| `flowlab-shared/` | Empty directory (no entries as of 2026-08-07) |
| `Dockerfile` | Containerized capture environment |
| `kind-config.yaml` | kind cluster configuration for the demo |
| `demo-pods.yaml` | Demo workloads that generate traffic for flow capture |
| `docker-run.sh` | Script that runs the capture container |
| `entrypoint.sh` | Container entrypoint that orchestrates the dump |

## KEY FACT
`flowlab/dump-hubble` and `flowlab/validate-hubble` are the ONLY other `main` packages in the module besides `cmd/flowguarder`. Do not add a third — prefer adding functions to the existing tools.

## WHERE TO LOOK
| Task | Location |
|---|---|
| Capture new flows from a cluster | `dump-hubble/main.go` — deploy kind with `kind-config.yaml` + `demo-pods.yaml`, run `docker-run.sh` |
| Validate a captured fixture | `validate-hubble <file>` |
| Re-run the demo analysis | `flowguarder analyze flowlab/hubble-flows-before.jsonl` (from repo root) |
| Modify the demo environment | `kind-config.yaml`, `demo-pods.yaml`, `Dockerfile`, `entrypoint.sh` |

## CONVENTIONS
- The 17MB `hubble-flows-before.jsonl` is load-bearing: consumed by frozen review gates (`review5_test.go`, `review6_test.go`), README quick-start, and `make test` (CI runs review5/review6 against this fixture). Do NOT delete, truncate, or regenerate it without checking those gates.
- Generated policy artifacts from this dataset land in untracked `policies-calico/`, `policies-hubble/`, `policies-hubble-cilium/` dirs; the old `policies2/` dir was removed in commit de4b49e ("output removal").
- `dump-hubble` emits raw protobuf flow JSON with `EmitUnpopulated: false` to avoid zero-valued enum fields that the Hubble parser would reject.

## ANTI-PATTERNS
- Do NOT create a third `main` package in this directory without a strong reason.
- Do NOT move or duplicate the 17MB fixture (`flowlab/hubble-flows-before.jsonl`) — it is tracked exactly where the review gates expect it (fixturePath fallback chain: `../../flowlab/` → `flowlab/` → `testdata/`).
- Do NOT couple flowlab tooling into `pkg/` or `cmd/` logic.

## NOTES
- `hubble-flows-before.jsonl` is tracked in git (committed 334abec) — CI and the frozen review gates depend on it; if git status shows it modified, restore it rather than regenerating.
