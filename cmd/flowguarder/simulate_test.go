package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runSimulate invokes the simulate subcommand in-process via Cobra.
// NOT parallel-safe (shared rootCmd/simFlags globals) — see TestSimulate.
func runSimulate(t *testing.T, args ...string) (stdout, stderr *bytes.Buffer, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	// simFlags is a package-level global bound to pflag via StringVar in
	// init(); pflag applies those defaults ONLY at registration. A zero-value
	// reset here would wipe the --direction/--protocol defaults (flags absent
	// from args keep their current value), so instead snapshot the init-time
	// defaults and restore them after each run to prevent state leakage.
	saved := simFlags
	defer func() { simFlags = saved }()
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errBuf)
	err = rootCmd.Execute()
	return &out, &errBuf, err
}

func TestSimulate(t *testing.T) {
	// NOTE: no t.Parallel() — rootCmd and simFlags are package-level
	// globals; concurrent Execute() calls would race on shared state.
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		errSubstr string      // required substring of err.Error() when wantErr
		outSubstr string      // required substring of stdout when !wantErr
		wantJSON  *jsonResult // non-nil → parse stdout as JSON and compare exactly
	}{
		{
			name:      "allow text output",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--dst", "default/backend", "--port", "8080", "--protocol", "TCP"},
			wantErr:   false,
			outSubstr: "Ingress: allow\nEgress: allow\nMatching files:\n  - allow-egress-cnp.yaml\n  - allow-ingress-np.yaml",
		},
		{
			name:      "deny text output",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--dst", "default/backend", "--port", "9090", "--protocol", "TCP"},
			wantErr:   false,
			outSubstr: "Ingress: deny\nEgress: deny",
		},
		{
			name:      "undetermined text output",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "staging/web", "--dst", "staging/db", "--port", "80"},
			wantErr:   false,
			outSubstr: "Ingress: undetermined\nEgress: undetermined",
		},
		{
			name:    "json output exact structure",
			args:    []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--dst", "default/backend", "--port", "8080", "--protocol", "TCP", "--format", "json"},
			wantErr: false,
			wantJSON: &jsonResult{
				Source:        "default/frontend",
				Destination:   "default/backend",
				Traffic:       jsonTraffic{Ports: 8080, Protocol: "TCP"},
				Direction:     "both",
				Ingress:       "allow",
				Egress:        "allow",
				MatchingFiles: []string{"allow-egress-cnp.yaml", "allow-ingress-np.yaml"},
			},
		},
		{
			name:      "invalid protocol rejected",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--dst", "default/backend", "--protocol", "FOO"},
			wantErr:   true,
			errSubstr: `simulate: --protocol must be one of TCP, UDP, SCTP (got "FOO")`,
		},
		{
			name:      "conflicting src identification modes",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--src-labels", "app=x", "--dst", "default/backend"},
			wantErr:   true,
			errSubstr: "(--src, --src-labels)",
		},
		{
			name:      "labels + ip allowed",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--format", "text", "--src-labels", "app=frontend", "--src-ip", "10.0.0.5", "--dst-labels", "app=backend", "--dst-ip", "10.0.1.5", "--port", "8080", "--protocol", "TCP"},
			wantErr:   false,
			outSubstr: "Ingress: allow\nEgress: allow\nMatching files:\n  - allow-egress-cnp.yaml\n  - allow-ingress-np.yaml",
		},
		{
			name:      "shorthand + ip allowed",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--format", "text", "--src", "default/frontend", "--src-ip", "10.0.0.5", "--dst", "default/backend", "--dst-ip", "10.0.1.5", "--port", "8080", "--protocol", "TCP"},
			wantErr:   false,
			outSubstr: "Ingress: allow\nEgress: allow\nMatching files:\n  - allow-egress-cnp.yaml\n  - allow-ingress-np.yaml",
		},
		{
			name:    "entity + ip allowed",
			args:    []string{"simulate", "--policies", "../../testdata/simulate", "--format", "text", "--src-entity", "world", "--src-ip", "8.8.8.8", "--dst", "default/backend", "--port", "8080", "--protocol", "TCP"},
			wantErr: false,
		},
		{
			name:      "invalid direction",
			args:      []string{"simulate", "--policies", "../../testdata/simulate", "--src", "default/frontend", "--dst", "default/backend", "--direction", "sideways"},
			wantErr:   true,
			errSubstr: "--direction must be one of ingress, egress, both",
		},
		{
			name:      "missing required --policies",
			args:      []string{"simulate", "--src", "default/frontend", "--dst", "default/backend"},
			wantErr:   true,
			errSubstr: "simulate: --policies is required",
		},
		{
			name:      "invalid policy directory",
			args:      []string{"simulate", "--policies", "/nonexistent", "--src", "default/frontend", "--dst", "default/backend"},
			wantErr:   true,
			errSubstr: "simulate: load policies:",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runSimulate(t, tt.args...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (stdout: %s)", tt.errSubstr, stdout.String())
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.outSubstr != "" && !strings.Contains(stdout.String(), tt.outSubstr) {
				t.Fatalf("stdout missing %q:\n%s", tt.outSubstr, stdout.String())
			}
			if tt.wantJSON != nil {
				var got jsonResult
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
				}
				expJSON, _ := json.Marshal(tt.wantJSON)
				gotJSON, _ := json.Marshal(got)
				if string(expJSON) != string(gotJSON) {
					t.Fatalf("JSON mismatch:\nwant: %s\ngot:  %s", expJSON, gotJSON)
				}
			}
		})
	}
}
