# POLICY PACKAGE

## OVERVIEW
Generates source-agnostic `Policy` objects from flows then renders CiliumNetworkPolicy CRDs.

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add a new rule type (e.g. ICMP, L7) | `builder.go` — extend `IngressRule` / `EgressRule` |
| Change aggregation logic | `builder.go` — `Build()`, `buildIngressRules()`, `buildEgressRules()` |
| Modify Cilium CNP render | `cilium.go` — `buildCNPFromPolicy()`, `CNPIngressRule`, `CNPEgressRule` |
| Change YAML output format | `cilium.go` — `WriteCiliumYAML()`, `marshalCNPWithComment()` |
| Adjust BuildOptions flags | `builder.go` — `BuildOptions` struct (Cilium, DefaultDeny, Strict, ExcludeAnomalyTypes) |
| Update FQDN / L7 hint logic | `cilium.go` — `collectL7Hints()`, `findEgressHints()`, `dedupL7Rules()` |

## CONVENTIONS
- Two-phase design: `Build()` produces `Policy{WorkloadID, IngressRules, EgressRules}`, then `BuildCilium()` + `WriteCiliumYAML()` render Cilium-specific CRDs.
- Output sorted by `WorkloadID` (`namespace/name`) in `Build()` and by `Metadata.Name` in `BuildCilium()` — never skip.
- Filename sanitization: `sanitizeName()` strips non-alphanumeric chars (except `-` `.`), prepends `a` if leading char is not a letter. Used on CNP file names and metadata names.
- `DefaultDeny` appends a no-op `IngressRule` with description `"default deny-all ingress"` only when `IngressRules` already has entries.
- L7 DNS/HTTP hints from flows enrich rule descriptions and can spawn `L7Rules` blocks on port 53 ingress/egress.

## ANTI-PATTERNS
- Do NOT couple `Build()` with Cilium-specific fields (no `CNP*` types in builder).
- Do NOT mutate input `flows`, `patterns`, or `workloads` slices.
- Do NOT output non-deterministic policy or CNP order — always sort.
- Do NOT skip the `sort.Slice` by `WorkloadID` in `Build()` or by `Metadata.Name` in `BuildCilium()`.
- Do NOT generate manifests without the workload comment header (`CNPHeadComment` prepended via `marshalCNPWithComment()`).

## NOTES
- Tests exist: `builder_test.go` (1560 lines, 26+ table-driven scenarios) and `cilium_test.go` (155 lines). Keep them table-driven with `t.Parallel()` when adding coverage. CI Go version is 1.25 (setup-go@v5), matching go.mod 1.25.0.
- `cilium.go` uses `gopkg.in/yaml.v3` for YAML marshalling, avoiding the stdlib to support anchor output.
- `sanitizeName` and helper string functions (`contains`, `index`, `splitN`) are local shims to avoid extra stdlib imports.
