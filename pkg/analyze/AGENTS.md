# `pkg/analyze/` — Codebase Guide

## OVERVIEW
Flow classification, workload resolution, pattern aggregation, time baselining, and service hints for the flowguarder offline analysis pipeline.

## WHERE TO LOOK

| Task | File |
|---|---|
| Peer type classification (ingress/egress/dns/apiserver/pod-pod) | `classify.go` |
| Workload name resolution, grouping, hash stripping | `workload.go` |
| Traffic pattern aggregation (count, bytes, first/last seen) | `stats.go` |
| Time-distribution baseline computation (mean, stddev) | `baseline.go` |
| Service name resolution from hints or kubeconfig | `service.go` |

## CONVENTIONS

- **Purity**: All exported functions are pure — no I/O, no randomness, no global state mutation.
- **Sort-before-return**: Every function that returns a slice sorts it deterministically before returning (`sort.Strings`, `sort.SliceStable` by key).
- **Nil-safety**: `ComputePatterns(nil, …)` returns `[]Pattern{}`, `ComputeBaseline(nil)` returns `nil`, `SortByCount(nil)` returns `[]Pattern{}`.
- **Label priority for workload names**: `app` > `app.kubernetes.io/name` > `app.kubernetes.io/component` > `name` > `k8s-app` > `job-name` > `controller-uid`.
- **Workload kind detection**: `job-name`/`controller-uid` → CronJob; `k8s-app` → DaemonSet; `app`/`app.kubernetes.io/name` → Deployment; otherwise Unknown.
- **Hash stripping**: `StripPodTemplateHash` removes trailing `-<hex-or-alnum>` suffixes to normalize pod names into workload names.
- **Slice ownership**: `Classify` returns a *new* slice (copies each flow); `FilterDirection` appends to a fresh buffer. Callers never share mutable state with returned slices.
- **Private CIDRs**: `defaultPrivateCIDRs` (RFC 1918, 4193, CGNAT, loopback, link-local) are baked in via `init()`; pass `nil` to `IsPrivateIP` to use them.

## ANTI-PATTERNS

- Do NOT introduce I/O, network calls, or clock reads inside exported analyzers — `Classify`, `ComputePatterns`, `ComputeBaseline` must be deterministic.
- Do NOT mutate input slices or maps; always return a new slice or a fresh map.
- Do NOT return unsorted maps or non-deterministic output — sort keys before emitting.
- Do NOT skip the nil-safety contract: functions accepting `[]Flow` or `[]Pattern` must handle nil gracefully.
