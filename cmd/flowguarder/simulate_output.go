package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/flowguarder/flowguarder/pkg/simulate"
	"github.com/spf13/cobra"
)

func printText(cmd *cobra.Command, r simulate.Result, dir OutputDirection) {
	cmd.Println("=== flowGuarder Simulate ===")
	switch dir {
	case OutputDirIngress:
		cmd.Printf("Ingress: %s\n", string(r.Ingress))
	case OutputDirEgress:
		cmd.Printf("Egress: %s\n", string(r.Egress))
	default:
		cmd.Printf("Ingress: %s\n", string(r.Ingress))
		cmd.Printf("Egress: %s\n", string(r.Egress))
	}
	if len(r.MatchingFiles) > 0 {
		cmd.Println("Matching files:")
		for _, f := range r.MatchingFiles {
			cmd.Printf("  - %s\n", f)
		}
	}
}

type jsonResult struct {
	Source        string      `json:"source"`
	Destination   string      `json:"destination"`
	Traffic       jsonTraffic `json:"traffic"`
	Direction     string      `json:"direction"`
	Ingress       string      `json:"ingress,omitempty"`
	Egress        string      `json:"egress,omitempty"`
	MatchingFiles []string    `json:"matching_files,omitempty"`
}

type jsonTraffic struct {
	Ports     int    `json:"port"`
	Protocol  string `json:"protocol"`
	L7Name    string `json:"l7_name,omitempty"`
	L7Pattern string `json:"l7_pattern,omitempty"`
}

func formatEndpointName(ep simulate.Endpoint) string {
	if ep.Labels != nil {
		if name, ok := ep.Labels["app"]; ok && name != "" {
			return fmt.Sprintf("%s/%s", ep.Namespace, name)
		}
		keys := make([]string, 0, len(ep.Labels))
		for k := range ep.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(ep.Labels[k])
		}
		return fmt.Sprintf("%s/%s", ep.Namespace, sb.String())
	}
	if ep.IP != "" {
		return ep.IP
	}
	if ep.Entity != "" {
		return "entity:" + ep.Entity
	}
	return ep.Namespace
}

func printJSON(cmd *cobra.Command, src, dst simulate.Endpoint, traffic simulate.Traffic, r simulate.Result, dir OutputDirection) error {
	jr := jsonResult{
		Source:      formatEndpointName(src),
		Destination: formatEndpointName(dst),
		Traffic: jsonTraffic{
			Ports:     traffic.Port,
			Protocol:  traffic.Protocol,
			L7Name:    traffic.L7Name,
			L7Pattern: traffic.L7Pattern,
		},
		MatchingFiles: r.MatchingFiles,
	}
	switch dir {
	case OutputDirIngress:
		jr.Direction = "ingress"
		jr.Ingress = string(r.Ingress)
	case OutputDirEgress:
		jr.Direction = "egress"
		jr.Egress = string(r.Egress)
	default:
		jr.Direction = "both"
		jr.Ingress = string(r.Ingress)
		jr.Egress = string(r.Egress)
	}
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize JSON result: %w", err)
	}
	cmd.Println(string(data))
	return nil
}
