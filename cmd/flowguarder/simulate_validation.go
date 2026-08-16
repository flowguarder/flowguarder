package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/simulate"
)

// OutputDirection selects which directions to print in text output.
type OutputDirection int

const (
	OutputDirIngress OutputDirection = iota
	OutputDirEgress
	OutputDirBoth
)

// validEntities lists recognised Cilium entity identifiers.
var validEntities = []string{
	"world", "cluster", "host", "remote-node", "kube-apiserver",
}

func validateDirection(raw string) (OutputDirection, error) {
	switch strings.ToLower(raw) {
	case "ingress":
		return OutputDirIngress, nil
	case "egress":
		return OutputDirEgress, nil
	case "both":
		return OutputDirBoth, nil
	default:
		return OutputDirBoth, fmt.Errorf("simulate: --direction must be one of ingress, egress, both")
	}
}

func buildEndpoint(
	shorthand, ns, labels, ip, entity string,
	role string, // "source" or "destination"
) (simulate.Endpoint, error) {
	var ep simulate.Endpoint
	var identityCount int
	var identityFlags []string
	flagPrefix := "src"
	if role == "destination" {
		flagPrefix = "dst"
	}

	// A — shorthand (namespace/name) — identity mode
	if shorthand != "" {
		identityCount++
		identityFlags = append(identityFlags, "--"+flagPrefix)
		parts := strings.SplitN(shorthand, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return ep, fmt.Errorf(
				"simulate: %s: --%s must be namespace/name (got %q)",
				role, flagPrefix, shorthand,
			)
		}
		ep.Namespace = parts[0]
		ep.Labels = map[string]string{"app": parts[1]}
	}

	// B — labels (+ optional explicit namespace) — identity mode
	if labels != "" {
		identityCount++
		identityFlags = append(identityFlags, "--"+flagPrefix+"-labels")
		pns := ns
		if pns == "" {
			pns = "default"
		}
		ep.Labels = make(map[string]string)
		ls, err := parseLabelString(labels)
		if err != nil {
			return ep, fmt.Errorf("simulate: %s: %w", role, err)
		}
		for k, v := range ls {
			ep.Labels[k] = v
		}
		ep.Namespace = pns
	}

	// C — IP (orthogonal address dimension — combinable with exactly one identity mode)
	if ip != "" {
		ep.IP = ip
	}

	// D — entity — identity mode
	if entity != "" {
		identityCount++
		identityFlags = append(identityFlags, "--"+flagPrefix+"-entity")
		found := false
		for _, e := range validEntities {
			if entity == e {
				found = true
				break
			}
		}
		if !found {
			return ep, fmt.Errorf(
				"simulate: %s: --%s-entity must be one of: %s",
				role, flagPrefix, strings.Join(validEntities, ", "),
			)
		}
		ep.Entity = entity
	}

	// No identification at all
	if identityCount == 0 && ip == "" {
		return ep, fmt.Errorf(
			"simulate: %s: one identification mode is required (--%s or --%s-ip or --%s-entity or --%s-labels)",
			role, flagPrefix, flagPrefix, flagPrefix, flagPrefix,
		)
	}
	// Multiple identity modes are not allowed (IP is orthogonal, not an identity mode)
	if identityCount > 1 {
		return ep, fmt.Errorf(
			"simulate: %s: multiple identification flags (%s) — pick exactly one",
			role, strings.Join(identityFlags, ", "),
		)
	}

	return ep, nil
}

func parseLabelString(raw string) (map[string]string, error) {
	m := make(map[string]string)
	for _, rawKV := range strings.Split(raw, ",") {
		kv := strings.TrimSpace(rawKV)
		if kv == "" {
			continue
		}
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			return nil, fmt.Errorf("invalid label %q (expected k=v)", kv)
		}
		k := strings.TrimSpace(kv[:idx])
		v := kv[idx+1:]
		if k == "" {
			return nil, fmt.Errorf("empty key in label %q", kv)
		}
		if v == "" {
			return nil, fmt.Errorf("empty value in label %q", kv)
		}
		m[k] = v
	}
	return m, nil
}

func combineVerdicts(np, cnp simulate.Result) simulate.Result {
	return simulate.Result{
		Ingress:       combineSingleVerdict(np.Ingress, cnp.Ingress),
		Egress:        combineSingleVerdict(np.Egress, cnp.Egress),
		MatchingFiles: dedupSorted(append(np.MatchingFiles, cnp.MatchingFiles...)),
	}
}

func combineSingleVerdict(a, b simulate.Verdict) simulate.Verdict {
	if a == simulate.VerdictAllow || b == simulate.VerdictAllow {
		return simulate.VerdictAllow
	}
	if a == simulate.VerdictDeny || b == simulate.VerdictDeny {
		return simulate.VerdictDeny
	}
	return simulate.VerdictUndetermined
}

func dedupSorted(f []string) []string {
	if len(f) == 0 {
		return nil
	}
	sorted := make([]string, 0, len(f))
	seen := make(map[string]struct{}, len(f))
	for _, x := range f {
		if _, ok := seen[x]; !ok {
			seen[x] = struct{}{}
			sorted = append(sorted, x)
		}
	}
	sort.Strings(sorted)
	return sorted
}
