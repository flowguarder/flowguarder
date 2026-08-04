<p align="center"><img src="flowguarder-logo.png" alt="flowGuarder" width="200"></p>

# flowGuarder

**Kubernetes network flow analysis**

flowGuarder is a Go CLI that analyzes Kubernetes network flow logs from Hubble (Cilium) and Calico (including the Calico Goldmane gRPC API), aggregates them into traffic patterns, detects anomalies, and generates Kubernetes NetworkPolicy and CiliumNetworkPolicy YAML manifests. It runs completely offline: no cluster connectivity, no kubeconfig, no Kubernetes API access required. Flow logs can be captured once (via `hubble observe` or similar tools) and analyzed anywhere — including on an analyst laptop in an air-gapped environment.

Output is deterministic: keys and slices are sorted, so repeated runs on the same input always produce the same manifests.

---

## Features

- **100% offline / air-gapped** — zero cluster connectivity, no kubeconfig, no Kubernetes API access. Analyze flow logs captured elsewhere on any machine.
- **Multiple input formats** — Hubble JSON, Calico JSON, Calico Goldmane proto3 JSON. Source type is auto-detected by probing the first 4096 bytes of each file (`"verdict"` = Hubble, `"action"` = Calico, `"flow"` + `"sourceName"` = Goldmane).
- **Live mode** — stream from a Hubble Relay gRPC endpoint or tail a Calico flow log file for continuous analysis.
- **Anomaly detection** (7 detectors) — port-scan, rare-flow, asymmetric traffic, dropped flows, public egress, cross-namespace, TLS / unknown domain.
- **NetworkPolicy + CiliumNetworkPolicy generation** — deterministic policy manifests with optional default-deny stubs, symmetric ingress/egress rules (egress flows mirrored as destination ingress rules), and kube-apiserver sentinel rules (matching TCP/6443 and related ports to the apiserver CIDR).
- **Insight reports** — `--report` flags for top-flows, coverage, uncovered, egress-world, drops, and anomalies. Controlled via `--top-n` and `--generate-uncovered`.
- **Config-driven thresholds** — YAML config file for per-cluster customisation of CIDRs, excluded namespaces, detector thresholds, allowlists, and namespace profiles.
- **Deterministic output** — all keys and slices are sorted; repeated runs on identical input produce identical manifests.

---

## How it works

1. **Parse** — flowGuarder reads flow JSON from a file, directory, stdin, or live stream, auto-detecting the parser to use.
2. **Classify** — Each flow endpoint is classified (pod, world, apiserver, DNS) and assigned a `PeerType` and direction (ingress / egress / internal).
3. **Aggregate workloads** — Flows are grouped by source and destination workload IDs (`namespace/name`).
4. **Compute patterns** — Flow aggregates are keyed by (source, destination, port, protocol) with byte and packet counts.
5. **Detect anomalies** — Seven pure-function detectors scan the classified flows for policy violations.
6. **Build policies** — The abstract policy model is rendered into Kubernetes-Native `NetworkPolicy` or `CiliumNetworkPolicy` manifests.
7. **Write manifests** — YAML files are written to the output directory, one per workload.
8. **Print reports** — Selected report sections are printed to stdout (top-flows, coverage, drops, etc.).

---

## Installation

### Pre-built binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/flowguarder/flowguarder/releases).

---

## Quick start

Analyze a single Hubble JSON log file:

```console
$ flowguarder analyze hubble-flows.jsonl
=== flowGuarder Analysis Report ===
Flows parsed:      7551
Workloads:         6
Policies:          5
------------------------------------
====================================
```

Analyze all JSONL files in a directory:

```console
$ flowguarder analyze flows/
=== flowGuarder Analysis Report ===
Flows parsed:      13195
Workloads:         6
Policies:          5
------------------------------------
====================================
```

Pipe logs from stdin:

```console
$ cat hubble-flows.jsonl | flowguarder analyze -
=== flowGuarder Analysis Report ===
Flows parsed:      7551
Workloads:         6
Policies:          5
------------------------------------
====================================
```

Force a specific parser and emit JSON:

```console
$ flowguarder analyze calico-flows.log --source calico --format json
```

---

## Usage

### `flowguarder analyze [path]`

Offline analysis of flow log files, directories, or stdin (via `-`).

```console
$ flowguarder analyze flows.jsonl --output ./policies --report top-flows --report coverage --top-n 5
```

| Flag | Description | Default |
|---|---|---|
| `--config` | Path to YAML config file | (none) |
| `--source` | Flow source type: `auto`, `hubble`, `calico`, `goldmane` | `auto` |
| `--output` | Output directory for policy YAML manifests | (none — skip writing) |
| `--format` | Report output format: `text`, `json`, `both` | `text` |
| `--strict` | Disable safety margins for policy generation | `false` |
| `--default-deny` | Add deny-all stub policies | `false` |
| `--cilium` | Emit `CiliumNetworkPolicy` instead of `NetworkPolicy` | `false` |
| `--dry-run` | Only validate input, do not generate output | `false` |
| `-r, --report` | Repeatable report type: `top-flows`, `uncovered`, `coverage`, `egress-world`, `drops`, `anomalies` | (none) |
| `--top-n` | Number of top entries in reports | `10` |
| `--generate-uncovered` | Generate additional policies for uncovered traffic (requires `--output`) | `false` |

### `flowguarder live`

Stream live flows and run the same analysis pipeline. Either `--hubble-server` or `--calico-file` must be provided.

```console
$ flowguarder live --hubble-server 127.0.0.1:4245 --default-deny
$ flowguarder live --calico-file /var/log/calico/flows.json
```

| Flag | Description | Default |
|---|---|---|
| `--hubble-server` | Hubble Relay gRPC server address (`host:port`) | (none — required if no `--calico-file`) |
| `--calico-file` | Calico flow log file to tail | (none — required if no `--hubble-server`) |

Inherited from the root command:

| Flag | Description | Default |
|---|---|---|
| `--config` | Path to YAML config file | (none) |
| `--source` | Flow source type | `auto` |
| `--output` | Output directory for policy YAML manifests | (none) |
| `--format` | Report output format | `text` |
| `--strict` | Disable safety margins | `false` |
| `--default-deny` | Add deny-all stub policies | `false` |
| `--cilium` | Emit CiliumNetworkPolicy | `false` |
| `--kubeconfig` | Path to kubeconfig for dry-run diff (hidden) | (none) |

Ctrl-C or SIGTERM gracefully stops the stream.

### `flowguarder version`

Prints the flowguarder version.

```console
$ flowguarder version
1.0.0
```

---

## Report types

Reports are optional sections printed alongside the minimal summary header (flow count, workload count, policy count). Request any combination with `-r <type>`:

| Report | Description |
|---|---|
| `top-flows` | Top flow aggregates by total bytes. Groups by (source, destination, port, protocol) and returns the top-N sorted descending. |
| `coverage` | Policy coverage: percentage of flows and bytes covered by generated policies. |
| `uncovered` | Flows not covered by any generated policy. Lists source/destination pairs and the ports involved. |
| `egress-world` | Egress flows to public/external destinations (0.0.0.0/0) grouped by workload. |
| `drops` | Dropped or denied flows, grouped and sorted by bytes. Shows the responsible policy name or drop reason. |
| `anomalies` | All detected anomalies from the seven detector plugins, sorted by severity (high first), then workload, then type. |

Multiple report types can be requested in a single invocation:

```console
$ flowguarder analyze flows.jsonl --report top-flows --report coverage --report drops --top-n 5
```

---

## Anomaly detectors

flowGuarder runs seven deterministic detectors in a fixed order. All thresholds are configurable through the YAML config.

| Detector | ID | Severity | Description |
|---|---|---|---|
| Port scan | `port-scan` | High | Source workload contacts more distinct destination ports than `port_scan_threshold` (default: 10) within the time window (`port_scan_window_seconds`, default: 10). |
| Dropped flow | `dropped-flow` | Medium | Traffic was dropped or denied by a policy. Groups all drop events per source workload. |
| Namespace | `namespace` | Low-Medium | Cross-namespace traffic outside pairs declared in `allowed_namespace_pairs`. When no pairs are configured, severity is downgraded to low (informational). |
| Public egress | `public-egress` | Medium | Egress traffic to public (non-RFC1918) IPs from workloads not covered by `public_egress_allowlist_cidrs` or `known_good_external_endpoints`. DNS (port 53) is excluded by default. |
| TLS unknown domain | `tls-unknown-domain` | Medium | TLS or HTTP flows whose L7 SNI/Host does not match any domain in `known_good_external_endpoints`. Excludes DNS query names. |
| Asymmetric traffic | `asymmetric-traffic` | Medium | Workload with egress bytes greatly exceeding ingress bytes (default ratio threshold: 10:1). CronJob-labeled and operator workloads are excluded. |
| Rare flow | `rare-flow` | Low | Flow patterns with frequency below the configured percentile threshold (`rare_flow_threshold`, default: 0.001) and occurrence count under 10. Long-tail scrapers (more than 20 distinct patterns) are excluded. |

Anomaly IDs are deterministic SHA-256 hashes derived from the detector type, workload, and description — identical input always produces identical IDs.

---

## Configuration

The config file is optional; flowGuarder applies sensible defaults when no config is provided. Pass it with `--config` or place it at `/etc/flowguarder/config.yaml`.

A fully annotated example is included in this repository as `example-config.yaml`. Key configuration keys:

```yaml
# --- Cluster CIDRs ---
# RFC 1918, RFC 4193 ULA, and CGNAT ranges used for "internal" classification.
cluster_cidrs:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "fd00::/8"
  - "100.64.0.0/10"

# --- API Server CIDRs ---
# IP ranges carrying kube-apiserver traffic.
apiserver_cidrs:
  - "10.96.0.0/12"

# --- Excluded Namespaces ---
# Infrastructural namespaces whose flows are silently ignored.
excluded_namespaces:
  - "kube-system"
  - "calico-system"
  - "tigera-operator"

# --- Kubernetes DNS Ports ---
kube_dns_ports:
  - protocol: "UDP"
    port: 53
  - protocol: "TCP"
    port: 53

# --- Anomaly Thresholds ---
rare_flow_threshold: 0.001         # Percentile 0..1 below which a pattern is rare
port_scan_threshold: 10            # Distinct ports within window before flagging
port_scan_window_seconds: 10       # Time window for port-scan detection

# --- Public Egress Control ---
public_egress_known_good:
  - "docker.io"
  - "ghcr.io"
  - "gcr.io"
  - "k8s.gcr.io"
known_good_external_endpoints:
  - "pypi.org"
  - "registry.npmjs.org"
  - "apt.ubuntu.com"
public_egress_allowlist_cidrs: []  # Allowed public CIDRs

# --- Namespace Pairing ---
# Maps source namespace to allowed destination namespaces.
allowed_namespace_pairs: {}

# --- Per-Namespace Profiles ---
per_namespace_profiles:
  production:
    allowed_targets:
      - "kube-system/kube-dns:53/udp"
    disallowed_targets:
      - "external/untrusted:443/tcp"
    required_labels:
      - "app"
      - "version"

# --- API Server Sentinel Ports ---
# apiserver_ingress_ports: ...  # Default: TCP {9443, 8443, 5443, 6443}
# apiserver_egress_ports: ...  # Default: TCP {6443}

# --- Public Services ---
# Services rendered as a single match-all ingress rule.
# public_services:
#   - namespace: "kube-system"
#     name: "kube-dns"
#     ports:
#       - protocol: "UDP"
#         port: 53
```

---

## Building from source

Requires Go 1.25+.

Clone and build the binary:

```bash
git clone https://github.com/flowguarder/flowguarder.git
cd flowguarder
go build ./cmd/flowguarder   # produces ./flowguarder in the repo root
```

Or use the Makefile targets:

```bash
make build        # Build binary to bin/flowguarder
make test         # Run all tests (go test ./...)
make vet          # Run go vet ./...
```

Build release artifacts with GoReleaser:

```bash
goreleaser build --single-target
goreleaser release --snapshot
```

---

## Contributing

Issues and ideas are welcome. flowGuarder is licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
