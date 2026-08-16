package simulate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
)

// baseFixtureDir is relative to pkg/simulate/loader_test.go → ../../testdata/simulate.
const baseFixtureDir = "../../testdata/simulate"

func TestLoadPolicies_ValidNPDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	for _, f := range []string{"allow-ingress", "deny-ingress"} {
		src, err := os.ReadFile(filepath.Join(baseFixtureDir, f+"-np.yaml"))
		if err != nil {
			t.Skipf("fixture missing: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, f+"-np.yaml"), src, 0644); err != nil {
			t.Fatalf("copy fixture: %v", err)
		}
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies; want 2", len(policies))
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors; want 0", len(errs))
	}
	// Check allow-ingress.
	if policies[0].Kind != "NetworkPolicy" || policies[0].File != "allow-ingress-np.yaml" {
		t.Fatalf("policies[0] = %s/%s; want NetworkPolicy/allow-ingress-np.yaml", policies[0].Kind, policies[0].File)
	}
	np := policies[0].Network
	if np.Namespace != "default" {
		t.Fatalf("namespace = %q; want default", np.Namespace)
	}
	if np.Name != "allow-ingress" {
		t.Fatalf("name = %q; want allow-ingress", np.Name)
	}
	if np.Spec.PodSelector.MatchLabels["app"] != "backend" {
		t.Fatalf("podSelector app = %q; want backend", np.Spec.PodSelector.MatchLabels["app"])
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("expected 1 ingress rule; got %d", len(np.Spec.Ingress))
	}
	if len(np.Spec.Ingress[0].Ports) != 1 {
		t.Fatalf("rule ports count = %d; want 1", len(np.Spec.Ingress[0].Ports))
	}
	if *np.Spec.Ingress[0].Ports[0].Protocol != v1.ProtocolTCP || np.Spec.Ingress[0].Ports[0].Port.IntVal != 8080 {
		t.Fatalf("port = %d/%s; want 8080/TCP", np.Spec.Ingress[0].Ports[0].Port.IntVal, *np.Spec.Ingress[0].Ports[0].Protocol)
	}
}

func TestLoadPolicies_ValidCNPDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	for _, f := range []string{"allow-egress", "deny-egress"} {
		src, err := os.ReadFile(filepath.Join(baseFixtureDir, f+"-cnp.yaml"))
		if err != nil {
			t.Skipf("fixture missing: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, f+"-cnp.yaml"), src, 0644); err != nil {
			t.Fatalf("copy fixture: %v", err)
		}
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies; want 2", len(policies))
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors; want 0", len(errs))
	}
	if policies[0].Kind != "CiliumNetworkPolicy" || policies[0].File != "allow-egress-cnp.yaml" {
		t.Fatalf("policies[0] = %s/%s; want CiliumNetworkPolicy/allow-egress-cnp.yaml", policies[0].Kind, policies[0].File)
	}
	if policies[0].Cilium.Spec.EndpointSelector.MatchLabels["app"] != "frontend" {
		t.Fatalf("endpointSelector app = %q; want frontend", policies[0].Cilium.Spec.EndpointSelector.MatchLabels["app"])
	}
}

func TestLoadPolicies_MixedDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	fixtures := []struct {
		src string
		dst string
	}{
		{"allow-ingress-np.yaml", "allow-ingress-np.yaml"},
		{"allow-egress-cnp.yaml", "allow-egress-cnp.yaml"},
	}
	for _, f := range fixtures {
		src, err := os.ReadFile(filepath.Join(baseFixtureDir, f.src))
		if err != nil {
			t.Skipf("fixture missing: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, f.dst), src, 0644); err != nil {
			t.Fatalf("copy fixture %s: %v", f.dst, err)
		}
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies; want 2", len(policies))
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors; want 0", len(errs))
	}
	// Verify deterministic sort by relative file path.
	if policies[0].File > policies[1].File {
		t.Fatalf("policies not sorted: %s > %s", policies[0].File, policies[1].File)
	}
}

func TestLoadPolicies_MultiDoc(t *testing.T) {
	t.Parallel()

	// invalid-syntax.yaml has 2 docs: first valid (good-doc NetworkPolicy), second invalid.
	tmp := t.TempDir()
	src, err := os.ReadFile(filepath.Join(baseFixtureDir, "invalid-syntax.yaml"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "multi.yaml"), src, 0644); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies; want 1 (good-doc)", len(policies))
	}
	if policies[0].Network.Name != "good-doc" {
		t.Fatalf("policy name = %q; want good-doc", policies[0].Network.Name)
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors; want 1", len(errs))
	}
	if !strings.Contains(errs[0].Message, "multi.yaml") {
		t.Fatalf("error message %q does not mention filename multi.yaml", errs[0].Message)
	}
}

func TestLoadPolicies_InvalidSyntax(t *testing.T) {
	t.Parallel()

	// completely invalid YAML file — no valid docs at all.
	tmp := t.TempDir()
	bad := []byte("{{{ not yaml at all\n  [broken")
	if err := os.WriteFile(filepath.Join(tmp, "bad.yaml"), bad, 0644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	_, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if errs == nil {
		t.Fatal("expected LoadError; got nil")
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors; want 1", len(errs))
	}
	if !strings.Contains(errs[0].Message, "bad.yaml") {
		t.Fatalf("error message %q does not mention filename bad.yaml", errs[0].Message)
	}
}

func TestLoadPolicies_UnknownKind(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	src, err := os.ReadFile(filepath.Join(baseFixtureDir, "unknown-kind.yaml"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "unknown.yaml"), src, 0644); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}

	_, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if errs == nil {
		t.Fatal("expected LoadError; got nil")
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors; want 1", len(errs))
	}
	if !strings.Contains(errs[0].Message, "unsupported apiVersion/kind") {
		t.Fatalf("error message %q; want 'unsupported apiVersion/kind'", errs[0].Message)
	}
}

func TestLoadPolicies_FlowguarderGeneratedCNP_Header(t *testing.T) {
	t.Parallel()

	cnpDoc := `# Flowguarder-generated CiliumNetworkPolicy — do not edit manually.

---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: demo-client
  namespace: flowlab
spec:
  endpointSelector:
    matchLabels:
      app: demo-client
`

	tests := []struct {
		name        string
		yamlContent string
		wantKinds   []string
	}{
		{
			name:        "CiliumNetworkPolicy with flowguarder header",
			yamlContent: cnpDoc,
			wantKinds:   []string{"CiliumNetworkPolicy"},
		},
		{
			name: "NetworkPolicy with flowguarder header",
			yamlContent: `# Flowguarder-generated NetworkPolicy — do not edit manually.

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: demo-allow
  namespace: flowlab
spec:
  podSelector: {}
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
`,
			wantKinds: []string{"NetworkPolicy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmp := t.TempDir()
			if err := os.WriteFile(filepath.Join(tmp, "generated.yaml"), []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			policies, errs, err := LoadPolicies(tmp)
			if err != nil {
				t.Fatalf("LoadPolicies: %v", err)
			}
			if len(errs) != 0 {
				t.Fatalf("expected 0 load errors; got %d: %v", len(errs), errs)
			}
			if len(policies) != 1 {
				t.Fatalf("got %d policies; want 1", len(policies))
			}
			if policies[0].Kind != tt.wantKinds[0] {
				t.Fatalf("Kind = %q; want %q", policies[0].Kind, tt.wantKinds[0])
			}
		})
	}
}

func TestLoadPolicies_EmptyDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 0 {
		t.Fatalf("got %d policies; want 0", len(policies))
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors; want 0", len(errs))
	}
}

func TestLoadPolicies_NonYamlFileIgnored(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "ignore.txt"), []byte("apiVersion: v1\n"), 0644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(baseFixtureDir, "allow-ingress-np.yaml"))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "keep.yaml"), src, 0644); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies; want 1 (only keep.yaml)", len(policies))
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors; want 0", len(errs))
	}
}

func TestLoadPolicies_DirNotFound(t *testing.T) {
	t.Parallel()

	_, _, err := LoadPolicies("/nonexistent/flowguarder/testdata/simulate/fake")
	if err == nil {
		t.Fatal("expected error for non-existent dir; got nil")
	}
	if !strings.Contains(err.Error(), "cannot stat directory") {
		t.Fatalf("error %q; want 'cannot stat directory'", err.Error())
	}
}

func TestLoadPolicies_NSDefaulting_CNP(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cnp := `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: no-ns-cnp
spec:
  endpointSelector:
    matchLabels:
      app: test
  egress:
    - toEndpoints:
        - matchLabels:
            app: other
      toPorts:
        - ports:
            - port: "9999"
              protocol: TCP
`
	if err := os.WriteFile(filepath.Join(tmp, "no-ns.yaml"), []byte(cnp), 0644); err != nil {
		t.Fatalf("write CNP: %v", err)
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies; want 1", len(policies))
	}
	if policies[0].Cilium.Metadata.Namespace != "default" {
		t.Fatalf("CNP namespace = %q; want default", policies[0].Cilium.Metadata.Namespace)
	}
}

func TestLoadPolicies_NSDefaulting_NP(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	np := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-ns-np
spec:
  podSelector:
    matchLabels:
      app: test
  policyTypes:
    - Ingress
`
	if err := os.WriteFile(filepath.Join(tmp, "no-ns-np.yaml"), []byte(np), 0644); err != nil {
		t.Fatalf("write NP: %v", err)
	}

	policies, errs, err := LoadPolicies(tmp)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	if len(policies) != 1 {
		t.Fatalf("got %d policies; want 1", len(policies))
	}
	if policies[0].Network.Namespace != "default" {
		t.Fatalf("NetworkPolicy namespace = %q; want default", policies[0].Network.Namespace)
	}
}

func TestSplitYAMLDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantDocs []string
	}{
		{
			name:  "single document",
			input: "apiVersion: v1\nkind: Namespace\n",
			wantDocs: []string{
				"apiVersion: v1\nkind: Namespace\n",
			},
		},
		{
			name:  "two documents with ---",
			input: "---\napiVersion: v1\nkind: A\n---\napiVersion: v1\nkind: B\n",
			wantDocs: []string{
				"apiVersion: v1\nkind: A\n",
				"apiVersion: v1\nkind: B\n",
			},
		},
		{
			name:  "document end marker ...",
			input: "---\napiVersion: v1\nkind: A\n...\n---\napiVersion: v1\nkind: B\n",
			wantDocs: []string{
				"apiVersion: v1\nkind: A\n",
				"apiVersion: v1\nkind: B\n",
			},
		},
		{
			name:  "empty documents dropped",
			input: "---\n---\napiVersion: v1\n",
			wantDocs: []string{
				"apiVersion: v1\n",
			},
		},
		{
			name:     "whitespace-only documents dropped",
			input:    "---\n   \n---\nkind: A\n",
			wantDocs: []string{"kind: A\n"},
		},
		{
			name:  "no separator single doc",
			input: "kind: test\n",
			wantDocs: []string{
				"kind: test\n",
			},
		},
		{
			name:     "all empty",
			input:    "---\n---\n",
			wantDocs: []string{},
		},
		{
			name:     "comment-only document dropped between docs",
			input:    "# header\n\n---\nkind: A\n",
			wantDocs: []string{"kind: A\n"},
		},
		{
			name:     "comment-only stream all dropped",
			input:    "# a\n---\n# b\n---\n",
			wantDocs: []string{},
		},
		{
			name:     "comment inside doc stays attached",
			input:    "# header\nkind: A\n",
			wantDocs: []string{"# header\nkind: A\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := splitYAMLDocuments([]byte(tt.input))
			if len(got) != len(tt.wantDocs) {
				t.Fatalf("got %d docs; want %d", len(got), len(tt.wantDocs))
			}
			for i := range got {
				if string(got[i]) != tt.wantDocs[i] {
					t.Errorf("doc[%d] = %q; want %q", i, string(got[i]), tt.wantDocs[i])
				}
			}
		})
	}
}

func TestLoadPolicies_AllFixtures(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(baseFixtureDir)
	policies, errs, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if policies == nil {
		policies = []LoadedPolicy{}
	}
	if errs == nil {
		errs = []LoadError{}
	}
	// 6 valid: allow-ingress-np, deny-ingress-np, allow-egress-cnp,
	//   deny-egress-cnp, dns-allow-cnp, good-doc (from invalid-syntax.yaml first doc)
	// 2 errors: invalid-syntax.yaml bad doc 2, unknown-kind.yaml
	if len(policies) != 6 {
		t.Fatalf("got %d policies; want 6", len(policies))
	}
	if len(errs) != 2 {
		t.Fatalf("got %d errors; want 2", len(errs))
	}
	// Verify sorted order by relative file path.
	for i := 1; i < len(policies); i++ {
		if policies[i].File < policies[i-1].File {
			t.Fatalf("policies not sorted: %s < %s at index %d", policies[i].File, policies[i-1].File, i)
		}
	}
	// Check error messages name the correct files.
	errFiles := make(map[string]bool)
	for _, e := range errs {
		errFiles[e.File] = true
	}
	if !errFiles["invalid-syntax.yaml"] {
		t.Fatalf("expected LoadError for invalid-syntax.yaml; got files: %v", errFiles)
	}
	if !errFiles["unknown-kind.yaml"] {
		t.Fatalf("expected LoadError for unknown-kind.yaml; got files: %v", errFiles)
	}
}

func TestLoadPolicies_NPErrorPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fixture := "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: bad\nspec:\n  podSelector: 123\n"
	if err := os.WriteFile(filepath.Join(dir, "bad-np-podselector.yaml"), []byte(fixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	policies, errs, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies; got %d", len(policies))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 LoadError; got %d: %v", len(errs), errs)
	}
	if errs[0].File != "bad-np-podselector.yaml" {
		t.Fatalf("expected error.File=bad-np-podselector.yaml; got: %q", errs[0].File)
	}
}

func TestLoadPolicies_CNPErrorPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fixture := "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: bad\nspec:\n  endpointSelector: 123\n"
	if err := os.WriteFile(filepath.Join(dir, "bad-cnp-endpointselector.yaml"), []byte(fixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	policies, errs, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies; got %d", len(policies))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 LoadError; got %d: %v", len(errs), errs)
	}
	if errs[0].File != "bad-cnp-endpointselector.yaml" {
		t.Fatalf("expected error.File=bad-cnp-endpointselector.yaml; got: %q", errs[0].File)
	}
}

func TestSplitYAMLDocuments_DocEndAfterWhitespace(t *testing.T) {
	t.Parallel()
	docs := splitYAMLDocuments([]byte("---\n   \n...\nkind: test\n"))
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc; got %d: %q", len(docs), docs)
	}
	if string(docs[0]) != "kind: test\n" {
		t.Fatalf("unexpected doc: %q", docs[0])
	}
}

func TestLoadPolicies_FileNotDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: v1\nkind: ConfigMap\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, _, err := LoadPolicies(p)
	if err == nil {
		t.Fatal("expected error for file path; got nil")
	}
	if !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadPolicies_NoDocuments(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.yaml"), []byte("---\n---\n"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	policies, errs, err := LoadPolicies(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policies != nil {
		t.Fatalf("expected nil policies; got %v", policies)
	}
	if errs != nil {
		t.Fatalf("expected nil errs; got %v", errs)
	}
}
