package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"github.com/flowguarder/flowguarder/pkg/analyze"
	"github.com/flowguarder/flowguarder/pkg/anomaly"
	"github.com/flowguarder/flowguarder/pkg/config"
	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/flowguarder/flowguarder/pkg/ingest"
	_ "github.com/flowguarder/flowguarder/pkg/parser/calico" // register calico parser
	_ "github.com/flowguarder/flowguarder/pkg/parser/goldmane" // register goldmane parser
	_ "github.com/flowguarder/flowguarder/pkg/parser/hubble" // register hubble parser
	"github.com/flowguarder/flowguarder/pkg/parser"
	"github.com/flowguarder/flowguarder/pkg/policy"
	"github.com/flowguarder/flowguarder/pkg/report"
	"github.com/spf13/cobra"
)

// rootCmdData holds the flags for the root command so subcommands share them.
type rootCmdData struct {
	configPath       string
	source           string
	outputDir        string
	format           string
	strict           bool
	defaultDeny      bool
	cilium           bool
	kubeconfig       string
	reports          []string
	topN             int
	generateUncovered bool
}

var validReports = map[string]bool{
	"top-flows":      true,
	"uncovered":      true,
	"coverage":       true,
	"egress-world":   true,
	"drops":          true,
	"anomalies":      true,
}

// runAnalyzePipeline executes the full analyze pipeline and returns any error.
func runAnalyzePipeline(cmd *cobra.Command, sourcePath string, rd *rootCmdData) error {
	// 1. Load config
	cfg, err := config.Load(rd.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// 1b. Validate report flags
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
		return ingestDir(cmd, igSource.(*ingest.DirSource), cfg, rd, sourceType)
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
	defer reader.Close()

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

	return executeAnalysis(cmd, flows, cfg, rd)
}

// ingestDir handles directory scanning for DirSource.
func ingestDir(cmd *cobra.Command, src *ingest.DirSource, cfg config.Config, rd *rootCmdData, sourceType parser.Source) error {
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
		defer fc.Close()

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

	return executeAnalysis(cmd, allFlows, cfg, rd)
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
func executeAnalysis(cmd *cobra.Command, flows []flow.Flow, cfg config.Config, rd *rootCmdData) error {
	// 5. Aggregate workloads
	workloads := analyze.Aggregate(flows)

	// 6. Classify flows (set PeerType)
	flows = analyze.Classify(flows, cfg)

	// 7. Compute patterns
	patterns := analyze.ComputePatterns(flows, workloads)

	// 8. Detect anomalies
	anomalies := anomaly.RunAll(flows, patterns, workloads, cfg)

	// 9. Build policies
	pols := policy.Build(flows, patterns, workloads, anomalies, policy.BuildOptions{
		Cilium:      rd.cilium,
		DefaultDeny: rd.defaultDeny,
		Strict:      rd.strict,
		Config:      &cfg,
	})

	if len(pols) == 0 {
		fmt.Fprintln(os.Stderr, "flowguarder: no policies generated")
		return nil
	}

	// 10. Write YAML manifests
	outDir := rd.outputDir
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
		for _, p := range pols {
			writePolicyYAML(outDir, p, cfg)
		}
		cmd.Printf("Wrote policy files to %s\n", outDir)
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
				Cilium:      rd.cilium,
				DefaultDeny: rd.defaultDeny,
				Strict:      rd.strict,
				Config:      &cfg,
			})
			for _, p := range uncoveredPols {
				writePolicyYAML(outDir, p, cfg)
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

// writePolicyYAML writes a single policy as a Kubernetes NetworkPolicy manifest.
func writePolicyYAML(dir string, p policy.Policy, cfg config.Config) {
	np := buildNetworkPolicy(p, cfg)
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
	filename := fmt.Sprintf("%s-%s.yaml", sanitizeName(p.WorkloadNamespace), sanitizeName(p.WorkloadName))
	path := filepath.Join(dir, filename)
	os.WriteFile(path, append([]byte("---\n"), data...), 0644)
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

// parseWorkloadSelectorV2 parses a peer string into a NetworkPolicyPeer.
// When peer is "apiserver", it returns an IPBlock when cfg != nil && cfg.APIServerCIDRs is set,
// otherwise falls back to a namespaceSelector+podSelector matching all pods in kube-system.
func parseWorkloadSelectorV2(peer string, cfg *config.Config) (NetworkPolicyPeer, error) {
	if isWorldPeer(peer) {
		return NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}, nil
	}

	// Special handling for "apiserver" sentinel.
	if peer == "apiserver" {
		if cfg != nil && len(cfg.APIServerCIDRs) > 0 {
			return NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cfg.APIServerCIDRs[0].String()}}, nil
		}
		return NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
			PodSelector:       &metav1.LabelSelector{},
		}, nil
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
	return peerOut, nil
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
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   npManifestMeta         `json:"metadata"`
	Spec       networkingv1.NetworkPolicySpec `json:"spec"`
}

// buildNetworkPolicy converts a policy.Policy into a Kubernetes NetworkPolicy object.
func buildNetworkPolicy(p policy.Policy, cfg config.Config) *networkingv1.NetworkPolicy {
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
				MatchLabels: map[string]string{
					"app": p.WorkloadName,
				},
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
			peer, err := parseWorkloadSelectorV2(from, &cfg)
			if err != nil {
				continue
			}
			ir.From = append(ir.From, peer)
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
		for _, to := range rule.ToWorkloads {
			peer, err := parseWorkloadSelectorV2(to, &cfg)
			if err != nil {
				continue
			}
			er.To = append(er.To, peer)
		}
		for _, cidr := range rule.ToCIDRs {
			peer, err := parseWorkloadSelectorV2(cidr, &cfg)
			if err != nil {
				continue
			}
			er.To = append(er.To, peer)
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
