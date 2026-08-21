# PARSER PACKAGE

**Generated:** 2026-07-31 (refreshed 2026-08-07, updated 2026-08-21)

## OVERVIEW
`pkg/parser/` — flow-log parsing, source auto-detection, and registry-based parser selection for Hubble and Calico input formats.

## STRUCTURE
```
pkg/parser/
├── parser.go        # Parser interface, Source enum, FormatError type
├── detect.go        # parserRegistry + auto-detection + SelectParser wiring
├── parser_test.go   # Tests for detect.go
├── detect_test.go   # Tests for detect.go helpers
├── hubble/          # Hubble JSON parser (fail-fast on first parse error)
│   ├── parser.go    # 562 LOC: hubbleFlow structs, field mapping, parseLine
│   └── parser_test.go
├── calico/          # Calico JSON parser (log-and-skip bad lines)
│   ├── parser.go    # 265 LOC: calicoRecord, mapVerdict/direction/protocol
│   ├── parser_test.go
│   ├── syslog.go    # 120 LOC: Calico JSON-in-syslog (extractJSONFromSyslog)
│   └── syslog_test.go
├── goldmane/          # Calico Goldmane gRPC API parser (log-and-skip on errors)
│   ├── parser.go    # 337 LOC: FlowResult/FlowKey/Flow JSON structs, mapping
│   └── parser_test.go
```

## WHERE TO LOOK
| Task | File |
|---|---|
| Add a new flow-log format | `pkg/parser/<newformat>/parser.go` |
| Add detection probe rule | `pkg/parser/detect.go` (DetectFormat probes) |
| Change error types | `pkg/parser/parser.go` (FormatError, ErrAmbiguous, ErrUnknown) |
| Modify field mapping (Hubble) | `pkg/parser/hubble/parser.go` (mapFlow) |
| Modify field mapping (Calico) | `pkg/parser/calico/parser.go` (mapRecord) |
| Add/change Calico Goldmane format | `pkg/parser/goldmane/parser.go` (mapping), `pkg/parser/detect.go` (auto-detect probe) |

## CONVENTIONS
- Each subpackage **must** call `parser.RegisterParser(src, func() parser.Parser { return &Parser{} })` in its `init()` so the registry populates without import cycles.
- Auto-detection (`DetectFormat`) reads the first **4096 bytes** and probes the first non-empty line for: `"verdict"` → Hubble, `"action"` → Calico, `<` prefix → syslog.
- `SelectParser(src, override)`: if override != `SourceAuto`, the explicit override wins and detection is discarded; otherwise `src` (from auto-detect) is used.
- **Hubble parser**: fail-fast — any unparseable line returns `*FormatError` and stops parsing.
- **Calico parser** (`Parser`): log-and-skip — malformed lines are logged and skipped; parsing continues.
- **Calico syslog parser** (`SyslogParser`): log-and-skip — extraction errors and parse errors are logged; the underlying `parseLine` is reused so canonical mapping stays consistent.
- **Goldmane parser**: log-and-skip — the user's file may contain 6M+ records or be truncated; the parser logs decode errors and returns nil so partial data is still emitted.
- **Goldmane label dual-storage**: the Goldmane parser populates both `Flow.Source.Labels`/`Flow.Destination.Labels` and the top-level `SourceLabels`/`DestLabels` shortcut fields (mirroring Hubble). Endpoint labels are derived from `flow.sourceLabels`/`flow.destLabels` so `analyze.ResolveWorkload` can resolve workload names by label priority.
- **SourceGoldmane detection**: the first 4096 bytes must contain BOTH "flow" and "sourceName" to be classified as Goldmane; this prevents misclassification of old Calico format which also contains "action".
- Every subpackage ends with `var _ parser.Parser = (*Parser)(nil)` compile-time interface assertion.
- Hubble `Scanner` buffer is 32 KB; Calico / syslog scanners use 1 MB.

## ANTI-PATTERNS
- Do NOT import a subpackage (`hubble`, `calico`) from the root `parser` package — registry + `init()` avoids this import cycle.
- Do NOT add format-specific parsing logic to `detect.go` — probes only (`"verdict"`, `"action"`, `<`), no JSON unmarshalling or field mapping.
- Do NOT change Hubble's fail-fast behavior — callers expect deterministic abort on first bad record.
- Do NOT change Calico's skip behavior — log-and-skip is the contract for streaming resilience.
- Do NOT use `os.Open` inside `DetectFormat` — it accepts `io.Reader` so callers can pipe stdin. (Separate `DetectFormatFile` uses `os.Open`.)
- Do NOT add Goldmane-specific parsing logic to the old Calico `Parser` — keep the two formats separate; the user explicitly invokes `--source goldmane` for Goldmane data.
