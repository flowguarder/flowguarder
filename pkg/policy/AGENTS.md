# POLICY PACKAGE

## OVERVIEW
Generates source-agnostic `Policy` objects from flows, applies dual-carry (CIDR twins + entity sentinels on reserved peers), then renders CiliumNetworkPolicy CRDs.

## WHERE TO LOOK
| Task | Location |
|---|---|
| Add a new rule type (e.g. ICMP, L7) | `builder.go` — extend `IngressRule` / `EgressRule` |
| Change aggregation logic | `builder.go` — `Build()`, `buildIngressRules()`, `buildEgressRules()` |
| Modify Cilium CNP render | `cilium.go` — `buildCNPFromPolicy()`, `CNPIngressRule`, `CNPEgressRule` |
| Change YAML output format | `cilium.go` — `WriteCiliumYAML()`, `marshalCNPWithComment()` |
| Adjust BuildOptions flags | `builder.go` — `BuildOptions` struct (Cilium, DefaultDeny, Strict, ExcludeAnomalyTypes) |
| Update FQDN / L7 hint logic | `cilium.go` — `collectL7Hints()`, `findEgressHints()`, `dedupL7Rules()` |
| Modify NetPol CIDR twin generation | `builder.go` — `classifySyntheticPeer()` (~405) |
| Modify entity sentinel computation | `builder.go` — `reservedEntities()` (~370); `cilium.go` — `resolveEntitySet()` (~543) |
| Override port → apiserver | `builder.go` — `isKubeAPIServerPeer()` (~401), `isKubeAPIServerWorkload()` (~466); scoped override (Review9/BUG11) |

## DUAL-CARRY ENTITY CONTRACT

Reserved peers (host, remote-node, kube-apiserver, cluster, world) produce ONE rule carrying BOTH:

1. **NetPol CIDR twin** via `classifySyntheticPeer` → `FromWorkloads`/`ToCIDRs` — byte-identical rule for NetworkPolicy compatibility.
2. **Cilium entity sentinel** via `reservedEntities` → `FromEntities`/`ToEntities`.

`BuildCilium` / `buildCNPFromPolicy` (cilium.go): renders the ENTITY form and **skips the CIDR twins when entities exist**.

`resolveEntitySet` (cilium.go ~543-580): expands entity sentinels with host↔remote-node closure (host implies remote-node, remote-node implies host). E.g. kube-dns/apiserver 6443 resolves to `{host, kube-apiserver, remote-node}`.

World egress → `0.0.0.0/0` twin transform in builder.go: CLI's `isWorldPeer` recognizes `"world"`/`"entity:world"` so world egress emits `toEntities: [world]` + world twin.

The abstract `Policy` model in builder.go holds both representations; renderers choose.

## CONVENTIONS
- Two-phase design: `Build()` produces `Policy{WorkloadID, IngressRules, EgressRules}` where reserved-peer rules carry BOTH NetPol CIDR twins and Cilium entity sentinels (dual-carry); `BuildCilium()` + `WriteCiliumYAML()` render the Cilium entity form and skip CIDR twins when entities exist.
- Output sorted by `WorkloadID` (`namespace/name`) in `Build()` and by `Metadata.Name` in `BuildCilium()` — never skip.
- Filename sanitization: `sanitizeName()` strips non-alphanumeric chars (except `-` `.`), prepends `a` if leading char is not a letter. Used on CNP file names and metadata names.
- `DefaultDeny` appends a no-op `IngressRule` with description `"default deny-all ingress"` only when `IngressRules` already has entries.
- L7 DNS/HTTP hints from flows enrich rule descriptions and can spawn `L7Rules` blocks on port 53 ingress/egress.
- **Apiserver-port override (BUG11/Review9):** port-to-apiserver (`9443/8443/5443/6443` → `kube-apiserver` peer type) is NOW SCOPED — fires only for (a) reserved `kube-apiserver` label peers (`isKubeAPIServerPeer`) or (b) workloads matching `apiserver_workload_selector` (default `kube-system/kube-apiserver`) in `isKubeAPIServerWorkload`. Plain pub/pvt/world peers on these ports stay `world` (`0.0.0.0/0`).
- **NetworkPolicy service-range removal:** No longer emits `10.96.0.0/12` service-range CIDRs in rendered NetPol. Only node `/32` IPs + optional user `node_cidrs` from config.

## ANTI-PATTERNS
- Do NOT couple `Build()` with Cilium-specific fields (no `CNP*` types in builder).
- Do NOT mutate input `flows`, `patterns`, or `workloads` slices.
- Do NOT output non-deterministic policy or CNP order — always sort.
- Do NOT skip the `sort.Slice` by `WorkloadID` in `Build()` or by `Metadata.Name` in `BuildCilium()`.
- Do NOT generate manifests without the workload comment header (`CNPHeadComment` prepended via `marshalCNPWithComment()`).
- Do NOT remove the NetPol CIDR twins from the abstract model — the frozen CLI review gates (cmd/flowguarder/review5_test.go, review6_test.go) assert them.
- Do NOT emit CIDR twins in the Cilium render when entity sentinels exist (they'd be redundant/no-op in Cilium).
- Do NOT change `resolveEntitySet`'s host↔remote-node closure semantics without updating cilium_test.go expectations.

## NOTES
- Tests: `builder_test.go` (2746 LOC, 40+ table-driven scenarios incl. `TestIsKubeAPIServerWorkload` + `TestBuild_CalicoPvtWebhook_StaysWorld`) and `cilium_test.go` (1130 LOC). Keep them table-driven with `t.Parallel()`. Source LOC: `builder.go` 1157, `cilium.go` 712. CI Go 1.25 (setup-go@v5), matching go.mod 1.25.0.
- `cilium.go` uses `gopkg.in/yaml.v3` for YAML marshalling, avoiding the stdlib to support anchor output.
- `sanitizeName` and helper string functions (`contains`, `index`, `splitN`) are local shims to avoid extra stdlib imports.
