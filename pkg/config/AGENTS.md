# pkg/config — YAML Config Loading & Schema Validation

## OVERVIEW
Package `config` provides YAML config loading, Merge-on-top-of-defaults semantics, and schema validation for flowguarder CLI parameters.

## STRUCTURE
| File | LOC | Role |
|---|---|---|
| `config.go` | 492 | `Load`, `Default`, `Merge`, `Validate`, struct definitions, CIDR string→IPNet conversion |
| `config_test.go` | 1099 | Table-driven tests for defaults, partial YAML, validation errors, full YAML round-trip |

## WHERE TO LOOK
| Change | Location |
|---|---|
| Change default values | `Default()` func (line 168), `var Default*` constants (lines 23-75) |
| Add config key | `Config` struct (line 111), `configRaw` struct (line 395), `toConfig` (line 417), `Merge` (line 203), `Validate` (line 303), root `example-config.yaml` |
| Change validation rules | `Validate` method (line 303) |
| Change `apiserver_workload_selector` / `node_cidrs` semantics | Their structs (lines 105, 161) + consumers: `cmd/flowguarder/common_pipeline.go` (`parseWorkloadSelectorV2`), `pkg/policy/builder.go` (`isKubeAPIServerWorkload`) |

## CONVENTIONS
- `Load("")` → returns `Default()` with zero error. `Load(path)` on missing file returns wrapped `os.PathError`-style `fmt.Errorf`.
- Parse → `configRaw` (CIDRs as strings) → `toConfig()` (string→IPNet conversion) → `Merge(Default())` → `Validate()`. Fail-fast on first error.
- `Merge` fills only zero-valued fields: nil/empty slices, nil maps, zero scalars (0 floats, 0 ints). `AlwaysAllowDNS` is intentionally NOT merged — false is its zero value and must not be clobbered.
- `Default()` sets `ApiserverWorkloadSelector` to `&WorkloadSelector{Namespace: "kube-system", Name: "kube-apiserver"}` as the sentinel for port override.
- CIDR validation: YAML keys `cluster_cidrs`, `apiserver_cidrs`, `public_egress_allowlist_cidrs` parse via `net.ParseCIDR` in `cidrStringsToIPNet`. `node_cidrs` validated separately in `Validate` with the same parse.
- Port bounds: `kube_dns_ports` and `apiserver_*ports` allow 0-65535; `public_services[].egress_ports` require 1-65535 (port 0 excluded per TCP semantics).
- `public_services[ns/name].egress_allow_world` + `egress_ports`: dual-carry renders host/remote-node as `0.0.0.0/0` AND Cilium entity:world.
- `per_namespace_profiles`: `allowed_targets` / `disallowed_targets` use `"namespace/name:port/proto"` pattern strings; `required_labels` is a list of key names.
- No sorting/dedup applied anywhere in Load — caller responsibility. Determinism inherited from callers, not config.

## ANTI-PATTERNS
- Do NOT add a config key without updating `Config`, `configRaw`, `toConfig`, `Merge`, `Validate`, and root `example-config.yaml`.
- Do NOT change `Default()` values without checking review gates (`cmd/flowguarder/review5_test.go`, `review6_test.go`) which assert `Config.ClusterCIDRs` length and fed into `configIPNetSlice`.
- Do NOT mutate `Load` to return merged config without `Validate` — the three-phase sequence is critical.

## NOTES
- The gosec `G115` (int/uint16 conversion) exclusion in `.golangci.yml` is justified by `Validate()` enforcing ports 1-65535 before any conversion.
- `ParsePortSpec` (line 476) is a public utility accepting `"proto/port"` or `"port/protocol"` — used by callers outside the config loading path.
