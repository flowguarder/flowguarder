# cmd/flowguarder/tui — Interactive TUI Simulation

## OVERVIEW
Charmbracelet Bubble Tea terminal UI for `flowguarder simulate`. Picks source/destination objects from loaded policies, enters traffic parameters, and shows ingress/egress verdicts interactively.

## STRUCTURE
| File | LOC | Purpose |
|---|---|---|
| `model.go` | 435 | Core `Model` (tea.Model), `Run()`, `View()`, `Update()`, evaluation logic, verdict helpers |
| `inputs.go` | 166 | Focus constants (0–6), `initInputs()`, `setFocus()`, `updateInputs()`, `inputView()` |
| `lists.go` | 110 | `newList()`, custom delegate, `buildSrcItems`/`buildDstItems`, `selectableItem` |
| `result.go` | 68 | `resultView()`, verdict styles (allow=green, deny=red, undetermined=yellow) |
| `extract.go` | 203 | `ExtractSelectableObjects()`, workload/entity/CIDR extraction from policies |
| `extract_test.go` | 380 | 10 extraction tests (load, dedup, entity, CIDR, label priority, default ns) |
| `model_test.go` | 97 | 7 tests: Init, window resize, quit, view rendering |
| `stub.go` | 10 | Blank Charmbracelet imports to keep go.mod deps alive |

Also: `cmd/flowguarder/tui_smoke_test.go` (parent package, 5 flag-parsing smoke tests — not in this dir).

## WHERE TO LOOK
| Task | File |
|---|---|
| Change TUI layout/structure | `model.go` `View()` |
| Change focus navigation | `inputs.go` focus constants + `model.go` `Update()` tab/arrows |
| Change list appearance | `lists.go` delegate + `newList()` |
| Change verdict display | `result.go` `resultView()` |
| Change object extraction | `extract.go` `ExtractSelectableObjects()` |
| Change evaluation logic | `model.go` `evaluate()`, `combineVerdicts()` |
| Change Run entry point | `model.go` `Run()` — creates Model, calls InitModel, runs tea.Program |
| Add smoke test for flag | `../tui_smoke_test.go` (parent package) |

## CONVENTIONS
- Full-screen mode via `tea.WithAltScreen()`.
- `Model` is a value type (not pointer) — `var _ tea.Model = Model{}`.
- Focus cycling: Tab cycles src→dst→input fields→Evaluate→src; arrows navigate within lists/inputs/Evaluate.
- `list.Model` is value type — use `srcListInit`/`dstListInit` bool flags, never compare to nil.
- Filtering disabled on lists (`SetFilteringEnabled(false)`) to prevent Enter key conflicts.
- `Run()` signature: `Run(objects SelectableObjects, policyDir string, policies []simulate.LoadedPolicy) error`.
- All outputs sorted deterministically (`sort.Strings`, `slices.SortFunc`).
- Color scheme: K8s blue (ANSI 63) for focus, flowGuarder brown (ANSI 130) for header bg.
- `stub.go` keeps Charm deps alive in go.mod via blank imports.

## ANTI-PATTERNS
- Do NOT use pointer receiver methods on Model where value receivers work — tea.Model requires value semantics for View/Update.
- Do NOT compare `list.Model` to `nil` — it is a value type.
- Do NOT add filtering to lists — it breaks Enter key behavior.
- Do NOT put I/O or file access in the TUI package — policies are loaded by the CLI layer and passed in.
- Do NOT couple TUI to `pkg/parser` or `pkg/ingest` — the TUI only consumes `simulate.LoadedPolicy`.
