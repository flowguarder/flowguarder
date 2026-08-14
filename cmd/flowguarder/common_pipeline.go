package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/cmd/flowguarder/visualize"
	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	"github.com/flowguarder/flowguarder/pkg/parser"
	_ "github.com/flowguarder/flowguarder/pkg/parser/calico"   // register calico parser
	_ "github.com/flowguarder/flowguarder/pkg/parser/goldmane" // register goldmane parser
	_ "github.com/flowguarder/flowguarder/pkg/parser/hubble"   // register hubble parser
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/flowguarder/flowguarder/pkg/report"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

// rootCmdData holds the flags for the root command so subcommands share them.
type rootCmdData struct {
	configPath        string
	source            string
	outputDir         string
	format            string
	strict            bool
	defaultDeny       bool
	policyFormat      string
	cilium            bool // hidden alias for --policy-format=cnp
	kubeconfig        string
	reports           []string
	topN              int
	generateUncovered bool
	skipVisualize     bool
}

var validReports = map[string]bool{
	"top-flows":    true,
	"uncovered":    true,
	"coverage":     true,
	"egress-world": true,
	"drops":        true,
	"anomalies":    true,
}

// resolvePolicyFormat resolves the effective policy format from the user-provided
// flag and the detected source type.  When format is "auto" it defaults to cnp
// for Hubble and np for all non-Hubble sources.  Explicit "np" and "cnp" pass
// through unchanged.
func resolvePolicyFormat(format string, src parser.Source) string {
	if format != "auto" {
		return format
	}
	switch src {
	case parser.SourceHubble:
		return "cnp"
	default:
		// SourceCalico, SourceCalicoSyslog, SourceGoldmane, SourceUnknown,
		// SourceAuto — all default to NetworkPolicy for safety.
		return "np"
	}
}

// validatePolicyFormat returns an error when format is not one of
// the three accepted values: "auto", "np", "cnp".
func validatePolicyFormat(format string) error {
	switch format {
	case "auto", "np", "cnp":
		return nil
	default:
		return fmt.Errorf("invalid --policy-format %q (valid: auto, np, cnp)", format)
	}
}

// runAnalyzePipeline executes the full analyze pipeline and returns any error.
func runAnalyzePipeline(cmd *cobra.Command, sourcePath string, rd *rootCmdData) error {
	// 1. Load config
	cfg, err := config.Load(rd.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Validate policy-format flag before anything else
	if err := validatePolicyFormat(rd.policyFormat); err != nil {
		return err
	}

	// Validate report flags
	if len(rd.reports) > 0 {
		for _, r := range rd.reports {
			if !validReports[r] {
				return fmt.Errorf("unknown report %q (valid: top-flows, uncovered, coverage, egress-world, drops, anomalies)", r)
			}
		}
	}

	// 2b. Buffer stdin up-front when sourcePath is "-".
	var stdinData []byte
	if sourcePath == "-" {
		stdinData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	}

	// 3. Determine source type
	var sourceType parser.Source
	if rd.source != "" && rd.source != "auto" {
		sourceType = parseFlagSource(rd.source)
	} else {
		// Auto-detect from the input
		if sourcePath == "-" {
			// Detect from the buffered data, not os.Stdin directly.
			sourceType, err = parser.DetectFormat(bytes.NewReader(stdinData))
		} else {
			sourceType, err = autoDetectSource(sourcePath)
		}
		if err != nil {
			cmd.Printf("Warning: %v\n", err)
			sourceType = parser.SourceAuto
		}
	}

	// 4. Create ingest source
	var igSource ingest.Source
	if sourcePath == "-" {
		igSource = &bufStdinSource{data: stdinData}
	} else if info, err := os.Stat(sourcePath); err == nil && info.IsDir() {
		pattern, _ := regexp.Compile(`(?i)\.(json|jsonl|log)(\.gz)?$`)
		ds := &ingest.DirSource{Path: sourcePath, Pattern: pattern}
		igSource = ds
		// Use DirSource.Iterate for directories
		return ingestDir(cmd, igSource.(*ingest.DirSource), cfg, rd, sourceType, sourcePath)
	} else {
		igSource = ingest.NewFileSource(sourcePath)
	}

	// 4. Build parser and ingest flows
	p, err := parser.SelectParser(sourceType, parser.SourceAuto)
	if err != nil {
		return fmt.Errorf("selecting parser: %w", err)
	}

	reader, err := igSource.Open(context.Background())
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer func() { _ = reader.Close() }()

	var flows []flow.Flow
	err = p.Parse(reader, func(f flow.Flow) error {
		if err := f.Validate(); err != nil {
			return nil // skip unparseable flows
		}
		flows = append(flows, f)
		return nil
	})
	if err != nil {
		return fmt.Errorf("parsing flows: %w", err)
	}

	if len(flows) == 0 {
		fmt.Fprintln(os.Stderr, "flowguarder: no valid flows parsed")
		return nil
	}

	return executeAnalysis(cmd, flows, cfg, rd, sourceType, sourcePath)
}

// ingestDir handles directory scanning for DirSource.
func ingestDir(cmd *cobra.Command, src *ingest.DirSource, cfg config.Config, rd *rootCmdData, sourceType parser.Source, sourcePath string) error {
	var allFlows []flow.Flow

	p, err := parser.SelectParser(sourceType, parser.SourceAuto)
	if err != nil {
		return fmt.Errorf("selecting parser: %w", err)
	}

	err = src.Iterate(context.Background(), func(filePath string) error {
		fc, err2 := os.Open(filePath)
		if err2 != nil {
			return err2
		}
		defer func() { _ = fc.Close() }()

		var fileFlows []flow.Flow
		err2 = p.Parse(fc, func(f flow.Flow) error {
			if err2 := f.Validate(); err2 != nil {
				return nil
			}
			fileFlows = append(fileFlows, f)
			return nil
		})
		if err2 != nil {
			// On parse error for a single file, skip and continue
			cmd.Printf("Warning: skipping %s: %v\n", filePath, err2)
			return nil
		}
		allFlows = append(allFlows, fileFlows...)
		return nil
	})
	if err != nil {
		return fmt.Errorf("scanning directory: %w", err)
	}

	if len(allFlows) == 0 {
		fmt.Fprintln(os.Stderr, "flowguarder: no valid flows parsed from directory")
		return nil
	}

	return executeAnalysis(cmd, allFlows, cfg, rd, sourceType, sourcePath)
}

// autoDetectSource tries to detect the flow-log source from a file, directory or stdin.
func autoDetectSource(path string) (parser.Source, error) {
	if path == "-" {
		src, err := parser.DetectFormat(os.Stdin)
		if err != nil {
			return parser.SourceUnknown, err
		}
		return src, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return parser.SourceUnknown, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return parser.DetectFormatDir(path)
	}
	return parser.DetectFormatFile(path)
}

// parseFlagSource converts a string flag value to parser.Source.
func parseFlagSource(s string) parser.Source {
	switch s {
	case "hubble":
		return parser.SourceHubble
	case "calico":
		return parser.SourceCalico
	case "goldmane":
		return parser.SourceGoldmane
	case "auto":
		return parser.SourceAuto
	default:
		fmt.Fprintf(os.Stderr, "Warning: unknown source flag, defaulting to auto: %s\n", s)
		return parser.SourceAuto
	}
}

// executeAnalysis runs the full analysis pipeline on parsed flows.
func executeAnalysis(cmd *cobra.Command, flows []flow.Flow, cfg config.Config, rd *rootCmdData, sourceType parser.Source, sourcePath string) error {
	effectiveFormat := resolvePolicyFormat(rd.policyFormat, sourceType)

	// 5. Aggregate workloads
	workloads := analyze.Aggregate(flows)

	// 6. Infer apiserver CIDRs then classify flows (set PeerType)
	cfg.APIServerCIDRs = configIPNetSlice(analyze.InferAPIServerCIDRs(flows, cfg))
	flows = analyze.Classify(flows, cfg)

	// 7. Compute patterns
	patterns := analyze.ComputePatterns(flows, workloads)

	// 8. Detect anomalies
	anomalies := anomaly.RunAll(flows, patterns, workloads, cfg)

	// 9. Build policies
	pols := policy.Build(flows, patterns, workloads, anomalies, policy.BuildOptions{
		Cilium:      effectiveFormat == "cnp",
		DefaultDeny: rd.defaultDeny,
		Strict:      rd.strict,
		Config:      &cfg,
	})

	if len(pols) == 0 {
		fmt.Fprintln(os.Stderr, "flowguarder: no policies generated")
		return nil
	}

	// Advisory: warn when Hubble source produces reserved-entity egress on NP format.
	if effectiveFormat == "np" && sourceType == parser.SourceHubble && hasReservedEntityEgress(pols) {
		fmt.Fprintln(os.Stderr, "Warning: NetworkPolicy cannot express egress to reserved peers (host/remote-node/kube-apiserver); use --policy-format=cnp or configure Cilium policy-cidr-match-mode: nodes")
	}

	// 10. Write YAML manifests
	outDir := rd.outputDir
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
		if effectiveFormat == "cnp" {
			if err := writeCiliumYAML(outDir, pols, flows, workloads); err != nil {
				return err
			}
		} else {
			for _, p := range pols {
				writePolicyYAML(outDir, p, cfg, workloads)
			}
		}
		cmd.Printf("Wrote policy files to %s\n", outDir)

		// 10a. Generate HTML visualization
		src := sourcePath
		if src == "-" {
			src = "stdin"
		}
		if err := writeVisualizationHTML(outDir, pols, src, rd.skipVisualize); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write visualization: %v\n", err)
		}
	}

	// 10b. Generate uncovered policies
	if rd.generateUncovered && len(outDir) > 0 {
		uncovered := report.UncoveredFlows(flows, pols)
		if len(uncovered) > 0 {
			cmd.Printf("Generating policies for %d uncovered flows ...\n", len(uncovered))
			// Second Build pass on uncovered flows only
			uncoveredPatterns := analyze.ComputePatterns(uncovered, workloads)
			uncoveredAnomalies := anomaly.RunAll(uncovered, uncoveredPatterns, workloads, cfg)
			uncoveredPols := policy.Build(uncovered, uncoveredPatterns, workloads, uncoveredAnomalies, policy.BuildOptions{
				Cilium:      effectiveFormat == "cnp",
				DefaultDeny: rd.defaultDeny,
				Strict:      rd.strict,
				Config:      &cfg,
			})
			if effectiveFormat == "cnp" {
				if err := writeCiliumYAML(outDir, uncoveredPols, uncovered, workloads); err != nil {
					return err
				}
			} else {
				for _, p := range uncoveredPols {
					writePolicyYAML(outDir, p, cfg, workloads)
				}
			}
			cmd.Printf("Wrote %d uncovered policy files to %s\n", len(uncoveredPols), outDir)
		} else {
			cmd.Println("All flows are covered by existing policies.")
		}
	}

	// 11. Print report to stdout
	if rd.format == "json" || rd.format == "both" {
		printJSONReport(flows, patterns, workloads, anomalies, pols)
	}
	if rd.format == "text" || rd.format == "both" {
		printTextReport(cmd, flows, patterns, workloads, anomalies, pols, rd.reports, rd.topN)
	}

	return nil
}

func hasReservedEntityEgress(pols []policy.Policy) bool {
	for _, p := range pols {
		for _, rule := range p.EgressRules {
			for _, ent := range rule.ToEntities {
				if strings.Contains(ent, "host") ||
					strings.Contains(ent, "remote-node") ||
					strings.Contains(ent, "kube-apiserver") {
					return true
				}
			}
		}
	}
	return false
}

// warnIllegalSelectorKeysCNP walks the selectors of a built CiliumNetworkPolicy and
// emits a non-fatal warning to w for every selector key that does not match
// Kubernetes label-key syntax.  The writer is expected to be os.Stderr.
func warnIllegalSelectorKeysCNP(w io.Writer, policyFile string, cnp *policy.CiliumNetworkPolicy) {
	warned := make(map[string]bool)
	walkLabelMap := func(labels map[string]string) {
		for k := range labels {
			if !labelKeyRegex.MatchString(k) {
				if !warned[k] {
					warned[k] = true
					if _, err := fmt.Fprintf(w, "Warning: policy %s has Kubernetes-illegal selector key %q (must use label-key syntax: optional-dns-prefix/name where name is [a-zA-Z0-9_.-]+)\n", policyFile, k); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to write selector-key warning: %v\n", err)
					}
				}
			}
		}
	}

	if cnp.Spec.EndpointSelector.MatchLabels != nil {
		walkLabelMap(cnp.Spec.EndpointSelector.MatchLabels)
	}
	for i := range cnp.Spec.Ingress {
		for j := range cnp.Spec.Ingress[i].FromEndpoints {
			if cnp.Spec.Ingress[i].FromEndpoints[j].MatchLabels != nil {
				walkLabelMap(cnp.Spec.Ingress[i].FromEndpoints[j].MatchLabels)
			}
		}
	}
	for i := range cnp.Spec.Egress {
		for j := range cnp.Spec.Egress[i].ToEndpoints {
			if cnp.Spec.Egress[i].ToEndpoints[j].MatchLabels != nil {
				walkLabelMap(cnp.Spec.Egress[i].ToEndpoints[j].MatchLabels)
			}
		}
	}
}

// writeCiliumYAML converts policies to CiliumNetworkPolicy objects and writes
// them as YAML files. It also validates selector keys before writing.
func writeCiliumYAML(dir string, pols []policy.Policy, flows []flow.Flow, workloads analyze.Workloads) error {
	cnps := policy.BuildCilium(pols, flows, workloads)

	// Validate selector keys before writing.
	// We need to know each CNP's output filename to match warnings to files.
	for i := range cnps {
		fname := sanitizeName(cnps[i].Metadata.Namespace) + "-" + sanitizeName(cnps[i].Metadata.Name) + ".yaml"
		warnIllegalSelectorKeysCNP(os.Stderr, fname, &cnps[i])
	}

	return policy.WriteCiliumYAML(cnps, dir)
}

// writeVisualizationHTML generates an HTML visualization of the policy graph
// and writes it atomically to outDir as "flowguarder-visualization.html".
// If skip is true or outDir is empty the function is a no-op (returns nil).
func writeVisualizationHTML(outDir string, pols []policy.Policy, source string, skip bool) error {
	if skip || outDir == "" {
		return nil
	}

	g := visualize.BuildGraph(pols)

	tmpFile, err := os.CreateTemp(outDir, ".viz-*.html.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmpFile.Name()

	// Ensure cleanup on any failure path: close and remove the temp file.
	// os.Remove on a nonexistent path is a harmless no-op error.
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	if err := visualize.RenderHTMLWithSource(g, tmpFile, source); err != nil {
		return fmt.Errorf("rendering visualization: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpName, filepath.Join(outDir, "flowguarder-visualization.html")); err != nil {
		return fmt.Errorf("renaming visualization file: %w", err)
	}

	// #nosec G302 -- visualization HTML must stay world-readable (0644)
	if err := os.Chmod(filepath.Join(outDir, "flowguarder-visualization.html"), 0644); err != nil {
		return fmt.Errorf("chmod visualization file: %w", err)
	}

	return nil
}

// configIPNetSlice converts []string CIDRs to []*net.IPNet for the config.
func configIPNetSlice(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n != nil {
			out = append(out, n)
		}
	}
	return out
}

// writePolicyYAML writes a single policy as a Kubernetes NetworkPolicy manifest.
func writePolicyYAML(dir string, p policy.Policy, cfg config.Config, workloads analyze.Workloads) {
	np := buildNetworkPolicy(p, cfg, workloads)
	filename := fmt.Sprintf("%s-%s.yaml", sanitizeName(p.WorkloadNamespace), sanitizeName(p.WorkloadName))
	warnIllegalSelectorKeys(os.Stderr, filename, np)
	manifest := networkPolicyManifest{
		APIVersion: np.APIVersion,
		Kind:       np.Kind,
		Metadata: npManifestMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
			Labels:    np.Labels,
		},
		Spec: np.Spec,
	}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowguarder: failed to marshal policy %s: %v\n", p.WorkloadID, err)
		return
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, append([]byte("---\n"), data...), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "flowguarder: failed to write policy %s: %v\n", filename, err)
		return
	}
}

// labelKeyRegex validates Kubernetes label keys: optional DNS subdomain prefix
// (ending with /) followed by a name of [a-zA-Z0-9_.-].
// Cilium reserved key prefixes k8s: and reserved: are also accepted
// so that cross-namespace CNP selectors like "k8s:io.kubernetes.pod.namespace"
// and Cilium-internal keys like "reserved:world" pass without warning.
// Legal: "app", "app.kubernetes.io/name", "run.ai/workload-id",
//
//	"k8s:io.kubernetes.pod.namespace", "reserved:world"
//
// Illegal: "bad key*", ":app"
var labelKeyRegex = regexp.MustCompile(
	`^(?:k8s:|reserved:)?(?:[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[a-zA-Z0-9_.-]+$`,
)

// warnIllegalSelectorKeys walks the selectors of a built NetworkPolicy and
// emits a non-fatal warning to w for every selector key that does not match
// Kubernetes label-key syntax.  The writer is expected to be os.Stderr.
func warnIllegalSelectorKeys(w io.Writer, policyFile string, np *networkingv1.NetworkPolicy) {
	warned := make(map[string]bool)
	walkLabelMap := func(labels map[string]string) {
		for k := range labels {
			if !labelKeyRegex.MatchString(k) {
				if !warned[k] {
					warned[k] = true
					if _, err := fmt.Fprintf(w, "Warning: policy %s has Kubernetes-illegal selector key %q (must use label-key syntax: optional-dns-prefix/name where name is [a-zA-Z0-9_.-]+)\n", policyFile, k); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to write selector-key warning: %v\n", err)
					}
				}
			}
		}
	}
	if np.Spec.PodSelector.MatchLabels != nil {
		walkLabelMap(np.Spec.PodSelector.MatchLabels)
	}
	for i := range np.Spec.Ingress {
		for j := range np.Spec.Ingress[i].From {
			ps := np.Spec.Ingress[i].From[j].PodSelector
			if ps != nil && ps.MatchLabels != nil {
				walkLabelMap(ps.MatchLabels)
			}
		}
	}
	for i := range np.Spec.Egress {
		for j := range np.Spec.Egress[i].To {
			ps := np.Spec.Egress[i].To[j].PodSelector
			if ps != nil && ps.MatchLabels != nil {
				walkLabelMap(ps.MatchLabels)
			}
		}
	}
}

// shouldExpandToCIDRs returns true when the egress rule qualifies for the
// egress_allow_world /32→0.0.0.0/0 transform (or "apiserver" sentinel → 0.0.0.0/0).
// Three gates must all pass:
//
//  1. The workload (identified by the Policy) must match a PublicServiceSpec
//     whose EgressAllowWorld is true.
//  2. The rule must carry ToEntities that contain "host" or "remote-node".
//  3. The rule must have at least one /32 CIDR or the "apiserver" sentinel
//     in its ToCIDRs.
//
// If cfg is nil or the workload is not found in PublicServices the function
// returns false (safe default).
func shouldExpandToCIDRs(rule policy.EgressRule, p policy.Policy, cfg config.Config) bool {
	if len(cfg.PublicServices) == 0 {
		return false
	}

	// Gate 1: workload match + EgressAllowWorld flag.
	egressAllowWorld := false
	for _, svc := range cfg.PublicServices {
		if svc.Namespace == p.WorkloadNamespace && svc.Name == p.WorkloadName {
			egressAllowWorld = svc.EgressAllowWorld
			break
		}
	}
	if !egressAllowWorld {
		return false
	}

	// Gate 2: entity must contain "host" or "remote-node".
	hasHostEntity := false
	for _, ent := range rule.ToEntities {
		if strings.Contains(ent, "host") || strings.Contains(ent, "remote-node") {
			hasHostEntity = true
			break
		}
	}
	if !hasHostEntity {
		return false
	}

	// Gate 3: at least one /32 CIDR or the "apiserver" sentinel present.
	if len(rule.ToCIDRs) == 0 {
		return false
	}
	has32 := false
	for _, c := range rule.ToCIDRs {
		if strings.HasSuffix(c, "/32") || c == "apiserver" {
			has32 = true
			break
		}
	}
	return has32
}

// expandToCIDRs replaces every /32 CIDR and the "apiserver" sentinel with
// 0.0.0.0/0, dedupes, and returns a sorted slice.  Non-/32 CIDRs are preserved.
func expandToCIDRs(cidrs []string) []string {
	expanded := make(map[string]bool)
	for _, c := range cidrs {
		if strings.HasSuffix(c, "/32") || c == "apiserver" {
			expanded["0.0.0.0/0"] = true
		} else {
			expanded[c] = true
		}
	}
	out := make([]string, 0, len(expanded))
	for c := range expanded {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func isWorldPeer(peer string) bool {
	switch peer {
	case "0.0.0.0/0", "pub", "pvt", "-":
		return true
	case "":
		return true
	}
	return false
}

// parseWorkloadSelectorV2 parses a peer string into a slice of NetworkPolicyPeer.
// When peer is "apiserver" and cfg.APIServerCIDRs is set, it returns one IPBlock
// peer per configured CIDR.  When apiserver CIDRs are absent it returns a single
// kube-system namespaceSelector+podSelector fallback peer.
// For all other selectors it returns a single-element slice.
func parseWorkloadSelectorV2(peer string, cfg *config.Config, workloads analyze.Workloads) ([]NetworkPolicyPeer, error) {
	if isWorldPeer(peer) {
		return []NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}}, nil
	}

	// Special handling for "apiserver" sentinel.
	if peer == "apiserver" {
		var peers []NetworkPolicyPeer

		if cfg != nil && len(cfg.APIServerCIDRs) > 0 {
			// Keep only host-route CIDRs (IPv4 /32, IPv6 /128).
			// Service-range CIDRs (e.g. 10.96.0.0/12) never match after DNAT.
			for _, c := range cfg.APIServerCIDRs {
				if c == nil {
					continue
				}
				ones, _ := c.Mask.Size()
				if ones == 32 || ones == 128 {
					peers = append(peers, NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: c.String()}})
				}
			}
		}

		if cfg != nil && len(cfg.NodeCIDRs) > 0 {
			for _, entry := range cfg.NodeCIDRs {
				_, cidr, err := net.ParseCIDR(entry)
				if err != nil {
					continue
				}
				if cidr != nil {
					peers = append(peers, NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr.String()}})
				}
			}
		}

		// Deterministic sort.
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].IPBlock.CIDR < peers[j].IPBlock.CIDR
		})

		// No host routes or node_cidrs — fall back to kube-system namespaceSelector.
		if len(peers) == 0 {
			return []NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
					PodSelector:       &metav1.LabelSelector{},
				},
			}, nil
		}

		return peers, nil
	}

	// Build a single peer for non-sentinel selectors.
	if _, cidr, err := net.ParseCIDR(peer); err == nil && cidr != nil {
		return []NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: cidr.String()}}}, nil
	}

	var podLabels map[string]string
	var namespace string

	for _, seg := range strings.Split(peer, ",") {
		trimmed := strings.TrimSpace(seg)
		if trimmed == "" {
			continue
		}

		// 1. If segment contains '=', treat as key=value label (highest priority).
		//    This handles keys with slashes like app.kubernetes.io/name=calico-apiserver.
		if key, value, ok := parseLabelSegment(trimmed); ok {
			if podLabels == nil {
				podLabels = make(map[string]string)
			}
			podLabels[key] = value
			continue
		}

		// 2. If segment contains '/' and no '=', treat as namespace/name.
		if slashIdx := strings.Index(trimmed, "/"); slashIdx >= 0 {
			potentialNS := trimmed[:slashIdx]
			name := trimmed[slashIdx+1:]
			if potentialNS != "" && name != "" {
				if namespace == "" {
					namespace = potentialNS
				}
				if podLabels == nil {
					podLabels = make(map[string]string)
				}
				// Resolve real stable labels from the workload when available.
				if workloads != nil {
					if wd, ok := workloads[analyze.WorkloadID(potentialNS+"/"+name)]; ok {
						stable := analyze.StripUnstableLabels(analyze.ResolveSelectors(wd))
						if len(stable) > 0 {
							// Merge workload labels into podLabels, explicit segments win.
							for k, v := range stable {
								if _, exists := podLabels[k]; !exists {
									podLabels[k] = v
								}
							}
							continue
						}
					}
				}
				podLabels["app"] = name
				continue
			}
		}

		// 3. Bare name → app: <segment>.
		if podLabels == nil {
			podLabels = make(map[string]string)
		}
		podLabels["app"] = trimmed
	}

	peerOut := NetworkPolicyPeer{}
	if podLabels != nil {
		peerOut.PodSelector = &metav1.LabelSelector{MatchLabels: podLabels}
	}
	if namespace != "" {
		peerOut.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": namespace}}
	}
	return []NetworkPolicyPeer{peerOut}, nil
}

type NetworkPolicyPeer = networkingv1.NetworkPolicyPeer

// parseLabelSegment parses a single comma-free segment into key/value or returns ok=false for invalid segments.
func parseLabelSegment(seg string) (key, value string, ok bool) {
	if seg == "" {
		return "", "", false
	}
	if seg == "-" {
		return "", "", false
	}
	if eqIdx := strings.Index(seg, "="); eqIdx >= 0 {
		key := seg[:eqIdx]
		value := seg[eqIdx+1:]
		if key != "" {
			return key, value, true
		}
	}
	return "", "", false
}

// parseWorkloadSelector parses a workload selector string into podSelector and namespaceSelector maps.
// Supported formats (matching policy.srcSelectorFor output):
//   - "key=value"            → podSelector={key:value}, namespaceSelector=nil
//   - "namespace/name"       → podSelector={app:name}, namespaceSelector={kubernetes.io/metadata.name:namespace}
//   - "name"                 → podSelector={app:name}, namespaceSelector=nil
//   - "k1=v1,k2=v2"          → podSelector={k1:v1, k2:v2}, namespaceSelector=nil
//   - "namespace/name,k1=v1" → podSelector={k1:v1}, namespaceSelector={kubernetes.io/metadata.name:namespace}
func parseWorkloadSelector(workload string) (podSelector map[string]string, namespaceSelector map[string]string) {
	if workload == "" {
		return nil, nil
	}

	podSelector = nil
	namespaceSelector = nil

	for _, seg := range strings.Split(workload, ",") {
		trimmed := strings.TrimSpace(seg)
		if trimmed == "" {
			continue
		}
		if key, value, ok := parseLabelSegment(trimmed); ok {
			if podSelector == nil {
				podSelector = make(map[string]string)
			}
			podSelector[key] = value
			continue
		}
		if slashIdx := strings.Index(trimmed, "/"); slashIdx >= 0 {
			ns := trimmed[:slashIdx]
			name := trimmed[slashIdx+1:]
			if name != "" {
				if podSelector == nil {
					podSelector = make(map[string]string)
				}
				podSelector["app"] = name
			}
			if ns != "" {
				namespaceSelector = map[string]string{"kubernetes.io/metadata.name": ns}
			}
			continue
		}
		if trimmed == "-" {
			continue
		}
		podSelector = map[string]string{"app": trimmed}
	}
	if podSelector == nil && namespaceSelector == nil {
		return nil, nil
	}
	return podSelector, namespaceSelector
}

// npManifestMeta is a minimal metadata subset for YAML marshaling that avoids
// metav1.ObjectMeta (whose CreationTimestamp marshals as "null" without omitempty).
type npManifestMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// networkPolicyManifest mirrors the shape of a NetworkPolicy YAML without the
// fields that cause "null" emission (e.g. creationTimestamp).
type networkPolicyManifest struct {
	APIVersion string                         `json:"apiVersion"`
	Kind       string                         `json:"kind"`
	Metadata   npManifestMeta                 `json:"metadata"`
	Spec       networkingv1.NetworkPolicySpec `json:"spec"`
}

// buildNetworkPolicy converts a policy.Policy into a Kubernetes NetworkPolicy object.
func buildNetworkPolicy(p policy.Policy, cfg config.Config, workloads analyze.Workloads) *networkingv1.NetworkPolicy {
	// Scope selector: derive from workload's stable labels, falling back to
	// {app: workloadName} for unknown/label-less workloads.
	podSelLabels := map[string]string{"app": p.WorkloadName}
	if wd, ok := workloads[analyze.WorkloadID(p.WorkloadID)]; ok {
		stable := analyze.StripUnstableLabels(analyze.ResolveSelectors(wd))
		if len(stable) > 0 {
			podSelLabels = stable
		}
	}

	np := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sanitizeName(p.WorkloadName),
			Namespace: p.WorkloadNamespace,
			Labels: map[string]string{
				"app":        p.WorkloadName,
				"managed-by": "flowguarder",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelLabels,
			},
		},
	}

	if len(p.IngressRules) > 0 {
		np.Spec.PolicyTypes = append(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	}
	if len(p.EgressRules) > 0 {
		np.Spec.PolicyTypes = append(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
	}

	for _, rule := range p.IngressRules {
		ir := networkingv1.NetworkPolicyIngressRule{}
		for _, from := range rule.FromWorkloads {
			peers, err := parseWorkloadSelectorV2(from, &cfg, workloads)
			if err != nil {
				continue
			}
			ir.From = append(ir.From, peers...)
		}
		for _, port := range rule.Ports {
			portVal := intstr.FromInt(int(port.Port))
			npPort := networkingv1.NetworkPolicyPort{
				Port: &portVal,
			}
			if port.Protocol != "" {
				proto := corev1.Protocol(port.Protocol)
				npPort.Protocol = &proto
			}
			ir.Ports = append(ir.Ports, npPort)
		}
		np.Spec.Ingress = append(np.Spec.Ingress, ir)
	}

	for _, rule := range p.EgressRules {
		er := networkingv1.NetworkPolicyEgressRule{}

		// Render ToWorkloads.
		for _, to := range rule.ToWorkloads {
			peers, err := parseWorkloadSelectorV2(to, &cfg, workloads)
			if err != nil {
				continue
			}
			er.To = append(er.To, peers...)
		}

		// Render ToNamespaces as namespaceSelector peer + empty podSelector.
		for _, ns := range rule.ToNamespaces {
			er.To = append(er.To, NetworkPolicyPeer{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns},
				},
				PodSelector: &metav1.LabelSelector{},
			})
		}

		// Render ToCIDRs (with egress_allow_world transform).
		cidrsToRender := rule.ToCIDRs
		if shouldExpandToCIDRs(rule, p, cfg) {
			cidrsToRender = expandToCIDRs(rule.ToCIDRs)
		}
		for _, cidr := range cidrsToRender {
			peers, err := parseWorkloadSelectorV2(cidr, &cfg, workloads)
			if err != nil {
				continue
			}
			er.To = append(er.To, peers...)
		}

		for _, port := range rule.ToPorts {
			portVal := intstr.FromInt(int(port.Port))
			npPort := networkingv1.NetworkPolicyPort{
				Port: &portVal,
			}
			if port.Protocol != "" {
				proto := corev1.Protocol(port.Protocol)
				npPort.Protocol = &proto
			}
			er.Ports = append(er.Ports, npPort)
		}
		np.Spec.Egress = append(np.Spec.Egress, er)
	}

	return np
}

func sanitizeName(s string) string {
	// Replace "/" and "." with "-" for filenames
	for _, r := range string([]rune("//.")) {
		s = replaceAllChar(s, rune(r), '-')
	}
	return s
}

// bufStdinSource holds stdin data in memory so it can be re-read by both
// detection and parsing without consuming the stream twice.
type bufStdinSource struct {
	data []byte
}

func (s *bufStdinSource) Open(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.data)), nil
}

func (s *bufStdinSource) Format() parser.Source { return parser.SourceAuto }

var _ ingest.Source = (*bufStdinSource)(nil)

func replaceAllChar(s string, old, new rune) string {
	var out []rune
	for _, r := range s {
		if r == old {
			out = append(out, new)
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}

func printJSONReport(flows []flow.Flow, patterns []anomaly.Pattern, workloads analyze.Workloads, anomalies []anomaly.Anomaly, policies []policy.Policy) {
	jr := jsonReport{
		FlowsTotal:   len(flows),
		Patterns:     len(patterns),
		Workloads:    len(workloads),
		Anomalies:    len(anomalies),
		Policies:     len(policies),
		AnomalyTypes: make(map[string]int),
	}
	for _, a := range anomalies {
		jr.AnomalyTypes[a.Type]++
	}

	buf, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(buf))
}

// ReportSet maps report names to true for O(1) lookup.
type ReportSet map[string]bool

// newReportSet builds a ReportSet from a slice of report names.
func newReportSet(reports []string) ReportSet {
	s := make(ReportSet, len(reports))
	for _, r := range reports {
		s[r] = true
	}
	return s
}

// hasReport returns true when any of the given report names is in the set.
func (rs ReportSet) hasReport(names ...string) bool {
	for _, n := range names {
		if rs[n] {
			return true
		}
	}
	return false
}

type jsonReport struct {
	FlowsTotal   int            `json:"flows_total"`
	Patterns     int            `json:"patterns_total"`
	Workloads    int            `json:"workloads"`
	Anomalies    int            `json:"anomalies"`
	Policies     int            `json:"policies"`
	AnomalyTypes map[string]int `json:"anomaly_types"`
}

// printTextReport outputs a human-readable text summary.
// When reports is empty, prints only a minimal summary (no anomalies, patterns, top-flows).
// When reports is non-empty, prints only the requested report sections.
func printTextReport(cmd *cobra.Command, flows []flow.Flow, patterns []anomaly.Pattern, workloads analyze.Workloads, anomalies []anomaly.Anomaly, policies []policy.Policy, reports []string, topN int) {
	rs := newReportSet(reports)

	cmd.Println("=== flowGuarder Analysis Report ===")
	cmd.Printf("Flows parsed:      %d\n", len(flows))
	cmd.Printf("Workloads:         %d\n", len(workloads))
	cmd.Printf("Policies:          %d\n", len(policies))

	// Minimal summary always printed.
	cmd.Println("------------------------------------")

	// Print requested report sections.
	if len(rs) == 0 {
		// No reports requested → nothing more after minimal summary.
		cmd.Println("====================================")
		return
	}

	// Anomalies
	if rs["anomalies"] {
		cmd.Printf("Anomalies:         %d\n", len(anomalies))
		for _, a := range anomalies {
			cmd.Printf("  [%s] %s (%s): %s\n", a.Severity, a.Type, a.Workload, a.Description)
		}
		cmd.Println("------------------------------------")
	}

	// Coverage
	if rs["coverage"] {
		cov := report.ComputeCoverage(flows, policies)
		cmd.Printf("Coverage: %.1f%% flows, %.1f%% bytes\n", cov.FlowPercent, cov.BytePercent)
		cmd.Println("------------------------------------")
	}

	// Top flows
	if rs["top-flows"] {
		printTopFlows(cmd, flows, workloads, rs, topN)
	}

	// Egress world
	if rs["egress-world"] {
		printEgressWorld(cmd, flows, workloads, rs, topN)
	}

	// Drops
	if rs["drops"] {
		printDrops(cmd, flows, workloads, rs)
	}

	// Uncovered
	if rs["uncovered"] {
		uncovered := report.UncoveredFlows(flows, policies)
		cmd.Printf("Uncovered flows:   %d\n", len(uncovered))
		if len(uncovered) > 0 {
			printUncoveredFlowsTable(cmd, uncovered)
		}
		cmd.Println("------------------------------------")
	}

	cmd.Println("====================================")
}

// printTopFlows prints the top-N flow aggregates by bytes.
func printTopFlows(cmd *cobra.Command, flows []flow.Flow, workloads analyze.Workloads, rs ReportSet, topN int) {
	top := report.TopFlows(flows, workloads, topN)
	if len(top) == 0 {
		cmd.Println("No flows to show.")
		return
	}
	cmd.Println("Top flows (by bytes)")
	cmd.Printf("%-24s %-24s %-6s %-8s %12s %8s\n", "Source", "Dest", "Port", "Proto", "Bytes", "Count")
	for _, f := range top {
		cmd.Printf("%-24s %-24s %-6d %-8s %12d %8d\n", f.Src, f.Dst, f.Port, f.Proto, f.Bytes, f.Count)
	}
	cmd.Println("------------------------------------")
}

// printEgressWorld prints top-N egress-world flow aggregates.
func printEgressWorld(cmd *cobra.Command, flows []flow.Flow, workloads analyze.Workloads, rs ReportSet, topN int) {
	top := report.EgressWorldFlows(flows, workloads, topN)
	if len(top) == 0 {
		cmd.Println("No egress-world flows.")
		return
	}
	cmd.Println("Egress-world flows (by bytes)")
	cmd.Printf("%-24s %-24s %-6s %-8s %12s %8s\n", "Source", "Dest", "Port", "Proto", "Bytes", "Count")
	for _, f := range top {
		cmd.Printf("%-24s %-24s %-6d %-8s %12d %8d\n", f.Src, f.Dst, f.Port, f.Proto, f.Bytes, f.Count)
	}
	cmd.Println("------------------------------------")
}

// printDrops prints dropped (non-allowed) flow aggregates.
func printDrops(cmd *cobra.Command, flows []flow.Flow, workloads analyze.Workloads, rs ReportSet) {
	dropped := report.DroppedFlows(flows, workloads, 0)
	if len(dropped) == 0 {
		cmd.Println("No dropped flows.")
		return
	}
	cmd.Println("Dropped flows (by bytes)")
	cmd.Printf("%-24s %-24s %-6s %-8s %12s %8s %12s\n", "Source", "Dest", "Port", "Proto", "Bytes", "Count", "Policy")
	for _, f := range dropped {
		cmd.Printf("%-24s %-24s %-6d %-8s %12d %8d %12s\n", f.Src, f.Dst, f.Port, f.Proto, f.Bytes, f.Count, f.Policy)
	}
	cmd.Println("------------------------------------")
}

// printUncoveredFlowsTable prints a compact table of uncovered flows.
func printUncoveredFlowsTable(cmd *cobra.Command, flows []flow.Flow) {
	// Show up to 20 for readability.
	max := 20
	if len(flows) < max {
		max = len(flows)
	}
	for _, f := range flows[:max] {
		srcW := analyze.ResolveWorkload(f.Source)
		dstW := analyze.ResolveWorkload(f.Destination)
		cmd.Printf("  %s/%s -> %s/%s %s:%d\n",
			srcW.Namespace, srcW.Name, dstW.Namespace, dstW.Name,
			f.Layer4.Protocol, f.Layer4.DestPort)
	}
	if len(flows) > max {
		cmd.Printf("  ... and %d more\n", len(flows)-max)
	}
}
