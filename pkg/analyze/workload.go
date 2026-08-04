package analyze

import (
	"regexp"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/flow"
)

// WorkloadKey defines the priority-ordered labels for workload name resolution.
// Higher-priority labels appear earlier in the slice and are checked first.
const (
	WorkloadKeyAppName          = "app"
	WorkloadKeyAppNameK8s       = "app.kubernetes.io/name"
	WorkloadKeyAppComponent     = "app.kubernetes.io/component"
	WorkloadKeyName             = "name"
	WorkloadKeyK8sApp           = "k8s-app"
	WorkloadKeyJobName          = "job-name"
	WorkloadKeyControllerUID    = "controller-uid"
)

// workloadKeyOrder defines the priority order for label-based name resolution.
var workloadKeyOrder = []string{
	WorkloadKeyAppName,
	WorkloadKeyAppNameK8s,
	WorkloadKeyAppComponent,
	WorkloadKeyName,
	WorkloadKeyK8sApp,
	WorkloadKeyJobName,
	WorkloadKeyControllerUID,
}

// WorkloadKind represents the type of Kubernetes workload resource.
type WorkloadKind string

const (
	// Deployment is a standard Deployment workload.
	Deployment WorkloadKind = "Deployment"
	// StatefulSet is a StatefulSet workload.
	StatefulSet WorkloadKind = "StatefulSet"
	// DaemonSet is a DaemonSet workload.
	DaemonSet WorkloadKind = "DaemonSet"
	// CronJob is a CronJob workload.
	CronJob WorkloadKind = "CronJob"
	// Unknown is an unrecognized workload kind.
	Unknown WorkloadKind = "Unknown"
)

// Workload represents a grouped set of pods belonging to the same workload.
type Workload struct {
	// Name is the resolved workload name.
	Name string
	// Namespace is the Kubernetes namespace.
	Namespace string
	// Labels are the pod labels used for grouping.
	Labels map[string]string
	// Kind is the Kubernetes workload resource type.
	Kind WorkloadKind
}

// WorkloadID uniquely identifies a workload as "namespace/name".
type WorkloadID string

// Workloads is a map of WorkloadID to Workload.
type Workloads map[WorkloadID]Workload

// SortedWorkloadIDs returns workload IDs sorted deterministically.
func (w Workloads) SortedIDs() []string {
	ids := make([]string, 0, len(w))
	for id := range w {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	return ids
}

var (
	// hashPattern matches a dash followed by 8+ hex characters at the end of a string.
	// This captures the standard pod-template-hash suffix (typically 10 hex chars).
	hashPattern = regexp.MustCompile(`-([0-9a-fA-F]{8,})$`)
	// alnumPattern matches a dash followed by 9+ alphanumeric characters at the end.
	alnumPattern = regexp.MustCompile(`-([a-zA-Z0-9]{9,})$`)
)

// StripPodTemplateHash removes a trailing pod-template-hash suffix from a name.
//
// A hash suffix is defined as a dash followed by either:
//   - 8 or more hexadecimal characters (e.g. "-7d3f9abc")
//   - 9 or more alphanumeric characters (e.g. "-abc1234567")
//
// If no suffix matches, the input is returned unchanged.
func StripPodTemplateHash(s string) string {
	if hashPattern.MatchString(s) {
		return hashPattern.ReplaceAllString(s, "")
	}
	if alnumPattern.MatchString(s) {
		return alnumPattern.ReplaceAllString(s, "")
	}
	return s
}

// WorkloadNameFromPodName extracts a workload name from a pod name by
// splitting on dash. For single-name pods (e.g. "single") the full name is
// returned. For two-part names the first part is returned (the second is a
// hash). For three or more parts the first two parts are joined.
//
// Examples:
//
//	"frontend-7d3f9abc" → "frontend"
//	"api-gw-pqr55"      → "api-gw"
//	"single"            → "single"
func WorkloadNameFromPodName(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) == 1 {
		return podName
	}
	if len(parts) == 2 {
		return parts[0]
	}
	return parts[0] + "-" + parts[1]
}

// ResolveWorkload maps a flow endpoint to a Workload by inspecting labels,
// falling back to pod-name prefix extraction.
//
// Name resolution priority (first matching label is used):
//
//	1. app
//	2. app.kubernetes.io/name
//	3. app.kubernetes.io/component
//	4. name
//	5. k8s-app
//	6. job-name
//	7. controller-uid
//
// Kind detection (based on label hints):
//   - job-name or controller-uid → CronJob
//   - k8s-app → DaemonSet
//   - app or app.kubernetes.io/name → Deployment
//   - otherwise → Unknown
func ResolveWorkload(endpoint flow.Endpoint) Workload {
	var name string
	var kind WorkloadKind

	// Resolve name from labels in priority order.
	for _, key := range workloadKeyOrder {
		if v, ok := endpoint.Labels[key]; ok && v != "" {
			name = StripPodTemplateHash(v)
			break
		}
	}

	// Fall back to pod-name prefix.
	if name == "" && endpoint.PodName != "" {
		name = WorkloadNameFromPodName(endpoint.PodName)
	}

	// Determine Kind from label hints.
	kind = detectKind(endpoint.Labels)

	return Workload{
		Name:      name,
		Namespace: endpoint.Namespace,
		Labels:    endpoint.Labels,
		Kind:      kind,
	}
}

// detectKind inspects labels to determine the workload Kind.
//
// Priority: job-name/controller-uid → CronJob; k8s-app → DaemonSet;
// app/app.kubernetes.io/name → Deployment; otherwise Unknown.
func detectKind(labels map[string]string) WorkloadKind {
	if _, ok := labels[WorkloadKeyJobName]; ok {
		return CronJob
	}
	if _, ok := labels[WorkloadKeyControllerUID]; ok {
		return CronJob
	}
	if _, ok := labels[WorkloadKeyK8sApp]; ok {
		return DaemonSet
	}
	if _, ok := labels[WorkloadKeyAppName]; ok {
		return Deployment
	}
	if _, ok := labels[WorkloadKeyAppNameK8s]; ok {
		return Deployment
	}
	return Unknown
}

// ResolveSelectors returns the workload's labels for use as a selector.
func ResolveSelectors(w Workload) map[string]string {
	return w.Labels
}

// Aggregate takes a slice of flows and groups Source and Destination
// endpoints into unique Workloads. Output is deterministic: workloads
// are deduplicated and returned in a map sorted by WorkloadID.
func Aggregate(flows []flow.Flow) Workloads {
	result := make(Workloads)
	for _, f := range flows {
		src := ResolveWorkload(f.Source)
		result[WorkloadID(src.Namespace+"/"+src.Name)] = src

		dst := ResolveWorkload(f.Destination)
		result[WorkloadID(dst.Namespace+"/"+dst.Name)] = dst
	}
	return result
}
