package analyze

import (
	"regexp"
	"strings"
)

// unstableLabelKeys holds label keys that are considered unstable — they change
// on pod restart/recreate and must not be baked into persistent NetworkPolicy
// selectors.
var unstableLabelKeys = map[string]bool{
	"pod-template-hash":             true,
	"controller-revision-hash":      true,
	"pod-index":                     true,
	"apps.kubernetes.io/pod-index":  true,
	"statefulset.kubernetes.io/pod-name": true,
	"controller-uid":                true,
	"projectcalico.org/namespace":   true,
	"projectcalico.org/orchestrator": true,
	"projectcalico.org/serviceaccount": true,
}

// stableKeys is the allow-list of label keys that are always kept, regardless
// of other strip heuristics (UUID values, knative/runai prefixes, etc.).
var stableKeys = map[string]bool{
	"app":                         true,
	"app.kubernetes.io/name":      true,
	"app.kubernetes.io/instance":  true,
	"app.kubernetes.io/component": true,
	"k8s-app":                     true,
	"name":                        true,
	"job-name":                    true,
}

// uuidRe matches a standard UUID (case-insensitive).
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// isUUID reports whether s matches a standard UUID pattern.
func isUUID(s string) bool {
	return uuidRe.MatchString(s)
}

// StripUnstableLabels returns a new map containing only the stable entries from
// labels. Unstable label keys (pod-template-hash, controller-revision-hash,
// any projectcalico.org/* key, knative/RunAI revision-UID keys, UUID-valued
// keys, etc.) are removed. The returned map is never nil when the input map
// is not nil — an empty map is returned instead.
//
// Stable label keys kept by default:
//
//	- app
//	- app.kubernetes.io/name
//	- app.kubernetes.io/instance
//	- app.kubernetes.io/component
//	- k8s-app
//	- name
//	- job-name
//
// In addition to the explicit deny-list, any key matching the prefix
// "projectcalico.org/" is stripped.
func StripUnstableLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return make(map[string]string)
	}

	result := make(map[string]string, len(labels))
	for k, v := range labels {
		// Stable keys are always kept — top-level guard.
		if stableKeys[k] {
			result[k] = v
			continue
		}

		// Strip if the key is in the deny-list.
		if unstableLabelKeys[k] {
			continue
		}

		// Strip any projectcalico.org/* key not already in the deny-list.
		if strings.HasPrefix(k, "projectcalico.org/") {
			continue
		}

		// Strip explicit generation/timestamp keys.
		if k == "pod-template-generation" {
			continue
		}

		// Strip Knative serving annotation prefixes.
		if strings.HasPrefix(k, "serving.knative.dev/") {
			continue
		}

		// Strip RunAI keys.
		if strings.HasPrefix(k, "run.ai/") {
			lk := strings.ToLower(k)
			// Strip any run.ai/ key containing "uid" (case-insensitive).
			if strings.Contains(lk, "uid") {
				continue
			}
			// Strip specific known run.ai workload-uid keys (compare the
			// local part after the prefix, case-insensitively).
			local := strings.ToLower(strings.TrimPrefix(lk, "run.ai/"))
			if local == "workload-id" || local == "cluster-top-owner-uid" || local == "top-owner-uid" {
				continue
			}
		}

		// Strip runai-gpu-group.
		if k == "runai-gpu-group" {
			continue
		}

		// Strip serviceUID.
		if k == "serviceUID" {
			continue
		}

		// Strip any key containing "UID" (case-insensitive).
		if strings.Contains(strings.ToLower(k), "uid") {
			continue
		}

		// Strip any key ending with "-uid" (case-insensitive).
		lowerK := strings.ToLower(k)
		if strings.HasSuffix(lowerK, "-uid") {
			continue
		}

		// Strip any key whose value is a UUID.
		if isUUID(v) {
			continue
		}

		result[k] = v
	}

	// Guarantee non-nil when input was non-nil.
	if result == nil {
		result = make(map[string]string)
	}
	return result
}
