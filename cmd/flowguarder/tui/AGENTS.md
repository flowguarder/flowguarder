# cmd/flowguarder/tui — Unified Interactive TUI

## OVERVIEW
Charmbracelet Bubble Tea full-screen UI with three tabs — **Analyze** (pick flow source + options form + reports + run), **Live** (Hubble/Calico streaming config + reports), **Simulate** (policy dir → src/dst → traffic params → verdicts) — plus a shared scrollable bottom output pane with inline CLI preview.

## STRUCTURE
| File | LOC | Purpose |
|---|---|---|
| `model.go` | 2117 | Core `Model`: Tab/Area enums, global key handling, `RunUnified`/`Run`, tab routing (`updateAnalyze/updateLive/updateSimulate`), `syncAreaFocus`, CLI preview builders, config save/load (`marshalConfigOutput`), bottom viewport |
| `form.go` | 1074 | `FormField` interface (9 methods) + 7 field types (TextField/NumberField/SelectField/MultiSelectField/PortListField/YAMLField/BoolField) + `Form` container; reflection-based `SetConfig` |
| `live.go` | 621 | `LiveTab`: source radio, Hubble addr field, Calico filepicker with synthetic ".." and authoritative `calicoCursorPos`/`calicoNav`; `ViewWithState` two-column layout |
| `analyze.go` | 443 | Analyze tab: picker + 28-field form, `renderAnalyzeBody` two-column layout, `refreshDirEntries`/`sourceSelection`/`movePickerCursorTo`/`cursorMinPos`/`reanchorCursor`/`stepPickerCursor`, area routing |
| `pickersafe.go` | 33 | `safeFilePickerView(filepicker.Model)` panic guard around bubbles v1.0.0 View() (nil FileInfo on vanished dir entries); returns placeholder "(directory changed — press up/down/enter to refresh)" |
| `analyze_reports.go` | 196 | `AnalyzeReports` multi-select toggle group (FormField); `RunButton` widget emitting `AnalyzeRunMsg` |
| `inputs.go` | 202 | Simulate focus constants (`focusPolicyDir`…`focusEval`), port/proto/L7 inputs |
| `extract.go` | 203 | `ExtractSelectableObjects()`: workloads/entities/CIDRs from `[]simulate.LoadedPolicy` |
| `lists.go` / `result.go` / `styles.go` / `stub.go` | 110/68/47/10 | src/dst lists; verdict view; TUI screenshot badge; blank Charm imports |
| Tests | ~3112 | `model_test.go` (1869), `extract_test.go` (380), `form_test.go` (354), `golden_test.go` (268), `capture_test.go` (178), `live_highlight_test.go` (103), `pickersafe_test.go` (88), `pickersource_test.go` (472 — `TestPickerSourceTracksHighlight`/`EnterConsistent`/`DescentRefresh`/`HandleAnalyzeRunUsesHighlightedEntry`/`ReproBadge*`/`CursorSourceInvariantUnderNavigation`/`OverlayDirStillHasDotDotRow`) |

## WHERE TO LOOK
| Task | Location |
|---|---|
| Global keys / tab switching / digit guard | `model.go` `Update()` (~455–530) |
| Area focus transitions | `model.go` `syncAreaFocus()` (~1103) |
| Per-tab key routing | `updateAnalyze` / `updateLive` / `updateSimulate` in `model.go` |
| Picker cursor invariant (analyze) | `analyze.go` `cursorMinPos`/`movePickerCursorTo`/`reanchorCursor` |
| New form field type | `form.go` (implement `FormField`, add to type-switches incl. `setFormFieldValue`) |
| Live Calico picker behavior | `live.go` `calicoNav` / `CalicoFilePath` |
| Reports toggle group | `analyze_reports.go` (used by BOTH Analyze and Live tabs) |
| Section title badges | `styles.go` `sectionTitle(focused, text)` |
| safeFilePickerView (analyze picker) | `pickersafe.go` (`safeFilePickerView(filepicker.Model)`) |
| Config → form / form → YAML | `form.go SetConfig` / `model.go marshalConfigOutput` |
| Golden snapshots | `golden_test.go` + `testdata/golden/*.txt` |

## NAVIGATION
Global: `1/2/3`+`←/→` switch tabs (suppressed while any editable input focused — see `isAnyEditableFocused`); `Tab`/`Shift+Tab` cycle areas; `ctrl+o` output pane; `q` quit (same guard); `?` help.
Area chains (visual order): Analyze `Picker→Form→Reports→Run`; Live `Selector→Input→Reports→Options→RunButton`; Simulate `PolicyDir→Src→Dst→Inputs→Eval`.
Live Reports: arrows/space drive the group cursor in place; `esc`→Options; Tab leaves. Calico pickers: `calicoCursorPos` is the single source of truth over `[..]+entries`; `calicoNav` re-aligns the internal bubbles cursor step-by-step.
Analyze picker semantics: `Values()["Source"]` and header Source line resolve via `AnalyzeTab.sourceSelection()` = highlighted entry (pos==0 → current directory; pos>=1 → Join(CurrentDirectory, dirEntries[pos-1])) — arrows alone drive Run, Enter optional (file-only). `dirEntries` mirrors bubbles v1.0.0 readDir ordering (dirs first alphabetical, hidden filtered), refreshed on tab init, ".." navigation, and directory changes. Cursor invariant enforced by `cursorMinPos`/`movePickerCursorTo`/`reanchorCursor` (pos 0 unreachable at "/" and "." where no ".." row renders).

## CONVENTIONS
- `Model` is a value type (`var _ tea.Model = Model{}`); no pointer receivers where value works.
- Runners are injected (`AnalyzeRunner`/`LiveRunner`/`PolicyLoader` via `UnifiedOpts`) — TUI never does pipeline I/O itself.
- `AnalyzeRunner` signature ends with `vizLayout string` (10 positional params); `LiveRunner` ends with `reports []string, vizLayout string`. `--viz-layout` is session-only (never persisted to config).
- Analyze tab auto-generates `flowguarder-visualization.html` alongside policies when `--output` is set (CLI parity; runner passes `skipVisualize: outputDir == ""`).
- Goldens: `UPDATE_GOLDEN=1 go test ./cmd/flowguarder/tui/ -run TestGoldenUISnapshots` regenerates; byte-exact except `containsOnly` models (seeded file pickers embed FS-specific sizes).
- Version string appears in goldens/capture tests — bump together with `version.go`.
- Colors: K8s blue ANSI 63 = focus, brown ANSI 130 = header.

## ANTI-PATTERNS
- Do NOT add filtering to lists (breaks Enter).
- Do NOT compare `list.Model` to nil; do NOT use pointer receivers on `Model`.
- Do NOT put I/O or `pkg/parser`/`pkg/ingest` coupling here — consume `simulate.LoadedPolicy` only.
- Do NOT let global shortcuts fire while a text field is focused — extend `isAnyEditableFocused`, don't bypass it.
- Do NOT hand-edit `testdata/golden/*` — regenerate via `UPDATE_GOLDEN=1`.
- Do NOT bypass `safeFilePickerView` by calling picker.View() directly (upstream v1.0.0 nil-FileInfo panic on vanished dir entries).
- Do NOT let `pickerCursorPos` rest on phantom slot 0 at "/" or "." — `cursorMinPos` guards this.
