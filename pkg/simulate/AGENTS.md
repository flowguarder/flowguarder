# simulate — policy-simulation engine

Policy-simulation engine: load K8s NetworkPolicy YAML manifests from a directory,
evaluate simulated L4/L7 flows against them, return allow/deny/undetermined verdict
per direction (ingress, egress).

## STRUCTURE

| File               | LOC   | Role |
| ---                | ---   | ---  |
| types.go           | 60    | Domain types: Endpoint\{Namespace,Labels,IP,Entity\}, Traffic\{Port,Protocol,L7Name,L7Pattern\}, Result\{Ingress,Egress,MatchingFiles\}, Verdict allow/deny/undetermined, LoadedPolicy\{File,Kind,Network,Cilium\}, LoadError\{File,Message\} |
| loader.go          | 246   | LoadPolicies: recursive WalkDir *.yaml/*.yml, splitYAMLDocuments (manual --- splitter), NP/CNP kind auto-detect via apiVersion/kind, ns defaults to "default", per-file LoadError continuation, deterministic sort by rel path |
| eval_np.go         | 469   | EvaluateNetworkPolicy: podSelector/namespaceSelector/ipBlock(cidr+Except)/port(intstr) matching, matchExpressions In/NotIn/Exists/DoesNotExist, default-deny on empty ingress/egress rules |
| eval_cnp.go        | 430   | EvaluateCiliumNetworkPolicy: endpointSelector, from/toEndpoints/CIDR/Entities, toFQDNs (MatchName exact + MatchPattern glob via path.Match), toServices, toPorts + DNS L7 (port 53), l7 override replaces only L7Name/L7Pattern |
| eval_np_test.go    | 958   | Table-driven tests for NetworkPolicy evaluator |
| eval_cnp_test.go   | 755   | Table-driven tests for CiliumNetworkPolicy evaluator |
| loader_test.go     | 680   | Table-driven tests for policy loader, splitYAMLDocuments |

## WHERE TO LOOK

| Task | Location |
| --- | --- |
| Add a verdict value | types.go:33-37 |
| Extend endpoint attributes | types.go:15-20 |
| Modify YAML loading | loader.go:31 (LoadPolicies), loader.go:129 (splitYAMLDocuments) |
| Add NP peer matching rule | eval_np.go:252 (peerMatches) |
| Add CNP entity/CIDR rule | eval_cnp.go:209-254 (matchIngress, matchEgress) |
| Add DNS L7 rule logic | eval_cnp.go:391 (dnsOK) |
| NS fallback "name" key | eval_np.go:310 (nsMatches) |
| Add eval test cases | eval_np_test.go, eval_cnp_test.go (table-driven, t.Parallel) |
| Fix loader behavior | loader.go:129 (splitYAMLDocuments — locked by loader_test.go + commit 895aaf0) |

## CONVENTIONS

- Table-driven tests with t.Parallel() everywhere across all *_test.go files.
- Evaluators are PURE (take []LoadedPolicy, no I/O, no file paths, no global state).
- Deterministic output — sort.Slice(policies by rel path) in loader, dedupSorted + sort.Strings on MatchingFiles.
- nil slices not empty slices (MatchingFiles returns nil when undetermined, not []).
- loader continues on per-file errors (returns []LoadError; unsupported kinds → LoadError).
- Protocol case-insensitive via strings.ToUpper throughout.
- CNP port rules use string ports parsed via strconv.Atoi (NOT intstr like NP).

## ANTI-PATTERNS

- Do NOT add I/O or file-path dependencies to evaluators — they must remain pure functions.
- Do NOT treat CNP empty ingress/egress as default-deny — that is NP semantics. CNP without policy-cidr-match-mode: nodes simply has no matching rules (returns undetermined).
- Do NOT change splitYAMLDocuments semantics — comment-only documents (and whitespace-only) are dropped (locked by loader_test.go and commit 895aaf0).
- Do NOT call sim CLI test in parallel — shared globals cause flaky output.
- Do NOT assume CNP port rules use intstr — they use string ports via strconv.Atoi (different from NP port matching at eval_np.go:417-428).

## NOTES

- nsMatches has a non-standard "name"-key fallback at line 310 that matches namespace name directly (in addition to kubernetes.io/metadata.name).
- Empty rule peers {} matches everything (eval_np.go:233-235).
- L7 override param (l7 *Traffic in EvaluateCiliumNetworkPolicy) replaces only L7Name/L7Pattern, not port/protocol.
- Test fixtures live in testdata/simulate/ (allow-ingress-np.yaml, allow-egress-cnp.yaml, deny-ingress-np.yaml, deny-egress-cnp.yaml, dns-allow-cnp.yaml, invalid-syntax.yaml, unknown-kind.yaml) — appear verbatim as relative paths in MatchingFiles when they contribute to a verdict.
- Two exported evaluator functions only: EvaluateNetworkPolicy, EvaluateCiliumNetworkPolicy
