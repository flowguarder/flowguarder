package flow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFlowValidate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		flow    Flow
		wantErr bool
	}{
		{
			name: "valid flow",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   Forwarded,
				Direction: Ingress,
			},
			wantErr: false,
		},
		{
			name: "missing Source.IP",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: ""},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   Forwarded,
				Direction: Ingress,
			},
			wantErr: true,
		},
		{
			name: "missing Destination.IP",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: ""},
				Verdict:   Forwarded,
				Direction: Ingress,
			},
			wantErr: true,
		},
		{
			name: "missing Time",
			flow: Flow{
				Time:          time.Time{},
				Source:        Endpoint{IP: "10.0.0.1"},
				Destination:   Endpoint{IP: "10.0.0.2"},
				Verdict:       Forwarded,
				Direction:     Ingress,
			},
			wantErr: true,
		},
		{
			name: "missing Verdict",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   "",
				Direction: Ingress,
			},
			wantErr: true,
		},
		{
			name: "missing Direction",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   Forwarded,
				Direction: "",
			},
			wantErr: true,
		},
		{
			name: "no L7 hints still valid",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   Dropped,
				Direction: Egress,
			},
			wantErr: false,
		},
		{
			name: "L7 hints present still valid",
			flow: Flow{
				Time:      now,
				Source:    Endpoint{IP: "10.0.0.1"},
				Destination: Endpoint{IP: "10.0.0.2"},
				Verdict:   Allow,
				Direction: Egress,
				L7:        &L7Hint{Type: "dns", Query: "example.com"},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.flow.Validate()
			if tc.wantErr {
				assert.Error(t, err, "expected validation error")
			} else {
				assert.NoError(t, err, "expected no validation error")
			}
		})
	}
}

func TestVerdictIsAllowed(t *testing.T) {
	tests := []struct {
		name   string
		v      Verdict
		allowed bool
	}{
		{"FORWARDED", Forwarded, true},
		{"ALLOW", Allow, true},
		{"REDIRECTED", Redirected, true},
		{"DROPPED", Dropped, false},
		{"DENIED", Denied, false},
		{"AUDIT", Audit, false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.allowed, tc.v.IsAllowed())
		})
	}
}
