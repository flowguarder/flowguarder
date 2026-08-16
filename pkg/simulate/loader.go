package simulate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/policy"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

// LoadPolicies recursively walks dir collecting *.yaml / *.yml files,
// auto-detecting NetworkPolicy vs CiliumNetworkPolicy via apiVersion/kind,
// and returns the parsed policies sorted by relative file path.
//
// Returns up to three values:
//
//	policies:  slice of successfully loaded policy files (possibly empty),
//	errors:    per-file load errors (for unsupported kinds or parse failures),
//	err:       top-level error if the directory itself was unreadable.
//
// Directory walking decisions:
//
//   - Non-existent / unreadable dir → err set (policies/errors nil/empty).
//   - Empty dir → empty slices, no error.
//   - Unsupported apiVersion/kind → LoadError (file continues).
//   - Parse failures → LoadError (file continues).
func LoadPolicies(dir string) ([]LoadedPolicy, []LoadError, error) {
	// Verify dir exists and is readable.
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("simulating: cannot stat directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("simulating: %q is not a directory", dir)
	}

	var yamlPaths []string // absolute paths
	var relPaths []string  // relative paths, parallel index

	// Walk recursively; skip sub-directories.
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			rel = name
		}
		yamlPaths = append(yamlPaths, path)
		relPaths = append(relPaths, rel)
		return nil
	}); err != nil {
		return nil, nil, err
	}

	if len(yamlPaths) == 0 {
		return []LoadedPolicy{}, []LoadError{}, nil
	}

	policies := make([]LoadedPolicy, 0, len(yamlPaths))
	loadErrors := make([]LoadError, 0, len(yamlPaths))

	for i, abspath := range yamlPaths {
		rel := relPaths[i]

		data, err := os.ReadFile(abspath)
		if err != nil {
			loadErrors = append(loadErrors, LoadError{
				File:    rel,
				Message: rel + ": " + err.Error(),
			})
			continue
		}

		docs := splitYAMLDocuments(data)
		for _, doc := range docs {
			var probe probeSpec
			if perr := yaml.Unmarshal(doc, &probe); perr != nil {
				loadErrors = append(loadErrors, LoadError{
					File:    rel,
					Message: rel + ": " + perr.Error(),
				})
				continue
			}

			result, lerr := loadDocument(rel, doc, &probe)
			if lerr != nil && lerr.Message != "" {
				loadErrors = append(loadErrors, *lerr)
				continue
			}
			if result != nil {
				policies = append(policies, *result)
			}
		}
	}

	// Deterministic sort by relative file path.
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].File < policies[j].File
	})

	if len(loadErrors) == 0 {
		loadErrors = nil
	}
	if len(policies) == 0 {
		policies = nil
	}

	return policies, loadErrors, nil
}

// splitYAMLDocuments splits multi-document YAML into individual []byte slices.
// A line whose trimmed content is exactly "---" starts a new document.
// A line equal to "..." is a document-end marker (dropped).
// Empty or comment-only documents (whitespace and lines starting with "#")
// are silently dropped.
func splitYAMLDocuments(data []byte) [][]byte {
	var docs [][]byte
	var cur []byte

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "---":
			// Start a new document at "---".
			if cur != nil && hasPolicyContent(cur) {
				if cur[len(cur)-1] != '\n' {
					cur = append(cur, '\n')
				}
				docs = append(docs, cur)
			}
			cur = nil
		case "...":
			// "..." document-end marker — drop if pending content is
			// whitespace-only or comment-only; otherwise keep it to be
			// flushed at the following "---" or EOF.
			if cur != nil && !hasPolicyContent(cur) {
				cur = nil
			}
		default:
			if cur != nil {
				cur = append(cur, '\n')
			}
			cur = append(cur, []byte(line)...)
		}
	}
	// Flush remainder.
	if cur != nil && hasPolicyContent(cur) {
		if cur[len(cur)-1] != '\n' {
			cur = append(cur, '\n')
		}
		docs = append(docs, cur)
	}
	return docs
}

// hasPolicyContent reports whether b contains at least one line that is
// non-blank and does not start with '#'.  Pure-whitespace and comment-only
// streams return false.
func hasPolicyContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

// probeSpec holds the minimal subset of a Kubernetes manifest needed for
// auto-detection of policy kind before full unmarshal.
type probeSpec struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

// loadDocument unmarshals data into the appropriate struct based on apiVersion/kind.
// Returns nil for unsupported kinds; a LoadError describes the issue.
func loadDocument(rel string, data []byte, probe *probeSpec) (*LoadedPolicy, *LoadError) {
	apiVer := probe.APIVersion
	kind := probe.Kind

	switch {
	case apiVer == "networking.k8s.io/v1" && kind == "NetworkPolicy":
		return loadNetworkPolicy(rel, data)
	case apiVer == "cilium.io/v2" && kind == "CiliumNetworkPolicy":
		return loadCiliumNetworkPolicy(rel, data)
	default:
		return nil, &LoadError{
			File:    rel,
			Message: fmt.Sprintf("unsupported apiVersion/kind: %s/%s", apiVer, kind),
		}
	}
}

// loadNetworkPolicy unmarshals the document into a networkingv1.NetworkPolicy.
// If metadata.namespace is absent, it defaults to "default".
func loadNetworkPolicy(rel string, data []byte) (*LoadedPolicy, *LoadError) {
	var np networkingv1.NetworkPolicy
	if err := yaml.Unmarshal(data, &np); err != nil {
		return nil, &LoadError{
			File:    rel,
			Message: err.Error(),
		}
	}
	if np.Namespace == "" {
		np.Namespace = "default"
	}
	return &LoadedPolicy{
		File:    rel,
		Kind:    "NetworkPolicy",
		Network: &np,
	}, nil
}

// loadCiliumNetworkPolicy unmarshals the document into a policy.CiliumNetworkPolicy.
// If metadata.namespace is absent, it defaults to "default".
func loadCiliumNetworkPolicy(rel string, data []byte) (*LoadedPolicy, *LoadError) {
	var cnp policy.CiliumNetworkPolicy
	if err := yaml.Unmarshal(data, &cnp); err != nil {
		return nil, &LoadError{
			File:    rel,
			Message: err.Error(),
		}
	}
	if cnp.Metadata.Namespace == "" {
		cnp.Metadata.Namespace = "default"
	}
	return &LoadedPolicy{
		File:   rel,
		Kind:   "CiliumNetworkPolicy",
		Cilium: &cnp,
	}, nil
}
