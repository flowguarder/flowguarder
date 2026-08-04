# REPORT PACKAGE

## OVERVIEW
Text/JSON report rendering + flow aggregation + policy-coverage matching for the flowguarder analysis pipeline.

## WHERE TO LOOK
| Task | Location |
|---|---|
| Text report rendering | `text.go` — `RenderText(r, w)`, `TextReport`, `TextPattern`, `TextAnomaly` |
| JSON report sorting + deterministic output | `json.go` — `RenderJSON(r, w)`, `sortMapKeys()`, `indentedJSON()`, `JSONReport` |
| Top-flows / egress-world / drops aggregation | `aggregates.go` — `TopFlows()`, `EgressWorldFlows()`, `DroppedFlows()`, `FlowAggregate` |
| Policy coverage / matching | `match.go` — `MatchFlow()`, `ComputeCoverage()`, `UncoveredFlows()`, `CoverageResult` |
| Helper aggregation key / sort | `aggregates.go` — `aggregateKey()`, `sliceSortByBytesDesc()` |
| Golden test fixtures | `testdata/` — `hubble_report.golden`, `hubble_json.golden`, `calico_report.golden`, `calico_json.golden` |

## CONVENTIONS
- `report.go` is intentionally a one-liner (`package report`) — the package is a file-per-function layout.
- Renderers target `io.Writer` — `RenderText(r, w)`, `RenderJSON(r, w)`. Never `fmt.Println`.
- JSON determinism: `sortMapKeys()` recursively sorts all `map[string]interface{}` keys; anomalies emitted in severity→workload→type order.
- Flat transfer structs (`TextReport`, `JSONReport`, `FlowAggregate`, `CoverageResult`) — never pass raw `pkg/flow.Flow` into output.
- Aggregations are pure: `TopFlows()`, `EgressWorldFlows()`, `DroppedFlows()` return new slices, never mutate input.
- `sliceSortByBytesDesc()` uses `sort.SliceStable` with deterministic tiebreak (`Src → Dst → Port → Proto`).
- Golden tests: hubble variants compare full output via `goldenfile`; calico goldens get sanity assertions only (no diff).
- Tests use table-driven layout + `t.Parallel()` + testify, matching repo convention.

## ANTI-PATTERNS
- Do NOT mutate input `flows` slices in aggregation/coverage functions — always return new slices.
- Do NOT output unsorted map keys — determinism contract applies to JSON key order and slice order.
- Do NOT call `fmt.Println` directly — all renderers must target `io.Writer`.
- Do NOT couple report logic to CLI flags — the cmd layer decides which reports to emit.

## NOTES
- `common_pipeline.go` has duplicate `printTextReport`/`printJSONReport` inline functions that call `TopFlows()` etc. directly instead of using `RenderText`/`RenderJSON` — this duplication exists but does not live in pkg/report.
- Benchmarks in `match_test.go`: `BenchmarkMatchFlow`, `BenchmarkComputeCoverage` — use for perf testing coverage logic.
- `aggregates_test.go` covers nil-input safety (nil `flows` → empty result, no panic).
- Tests: `text_test.go`, `json_test.go`, `aggregates_test.go`, `match_test.go`.
