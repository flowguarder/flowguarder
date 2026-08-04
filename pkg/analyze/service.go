package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/flow"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ParseServiceHint splits a Hubble-style service hint into namespace and name.
// Expected format: "namespace/name" (e.g. "default/kubernetes").
// Returns ("", "", false) when the hint is empty or malformed.
func ParseServiceHint(hint string) (namespace, name string, ok bool) {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return "", "", false
	}
	parts := strings.SplitN(hint, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ResolveFromLabel extracts a Kubernetes service name from an endpoint's labels.
// It looks for the label "app.kubernetes.io/service-name" and returns its value,
// or "" if the label is absent.
func ResolveFromLabel(e flow.Endpoint) string {
	if e.Labels == nil {
		return ""
	}
	return e.Labels["app.kubernetes.io/service-name"]
}

// ServiceResolver resolves Kubernetes Service names for flow endpoints.
// It is implemented by HintResolver (offline, hint-only) and
// KubeconfigResolver (live, cluster-access based).
type ServiceResolver interface {
	// Resolve returns the Kubernetes Service names for a flow's source
	// and destination. When no service can be resolved, the corresponding
	// string is empty.
	Resolve(f flow.Flow) (sourceService, destService string)
}

// HintResolver resolves service names exclusively from flow hint fields
// (Flow.Source.Service and Flow.Destination.Service). It requires zero
// cluster access and is suitable for offline mode.
type HintResolver struct{}

// NewHintResolver creates a new HintResolver.
func NewHintResolver() *HintResolver {
	return &HintResolver{}
}

// Resolve implements ServiceResolver by extracting service hints directly
// from the flow's Source.Service and Destination.Service fields.
func (r *HintResolver) Resolve(f flow.Flow) (sourceService, destService string) {
	sourceService = strings.TrimSpace(f.Source.Service)
	destService = strings.TrimSpace(f.Destination.Service)
	return
}

// KubeconfigResolver performs Kubernetes Service lookups using the
// client-go API. It is constructed with a kubernetes.Interface so that
// tests can inject a fake clientset.
//
// Resolution order per endpoint:
//
//  1. Flow hint (Source.Service / Destination.Service) — parse as
//     "namespace/name" and do a direct Service Get()
//
//  2. Label fallback — call ResolveFromLabel with the endpoint
//
//  3. Kubeconfig lookup — parse the hint as "namespace/name" and
//     perform a direct Get() call (may still resolve an unrelated service).
//
// When the kubeconfig client is nil the resolver falls back silently to
// hint and label lookups only.
type KubeconfigResolver struct {
	client kubernetes.Interface
}

// NewKubeconfigResolver creates a KubeconfigResolver from a Kubernetes
// clientset interface. Pass kubernetes.NewForConfig() for production
// or kubernetes.NewSimpleFake() for tests.
func NewKubeconfigResolver(client kubernetes.Interface) *KubeconfigResolver {
	return &KubeconfigResolver{client: client}
}

// Resolve implements ServiceResolver.
func (r *KubeconfigResolver) Resolve(f flow.Flow) (sourceService, destService string) {
	sourceService = r.resolveEndpoint(f.Source)
	destService = r.resolveEndpoint(f.Destination)
	return
}

func (r *KubeconfigResolver) resolveEndpoint(e flow.Endpoint) string {
	// 1. Hint-first (namespace/name)
	hint := strings.TrimSpace(e.Service)
	if ns, name, ok := ParseServiceHint(hint); ok {
		if r.client != nil {
			if svc, err := r.client.CoreV1().Services(ns).Get(
				context.Background(),
				name,
				metav1.GetOptions{},
			); err == nil && svc != nil {
				return svc.Name
			}
		}
		// Hint parsed but no client or lookup failed — return hint itself so
		// downstream code still sees the raw hint value.
		return fmt.Sprintf("%s/%s", ns, name)
	}

	// 2. Label fallback
	if svc := ResolveFromLabel(e); svc != "" {
		return svc
	}

	return ""
}
