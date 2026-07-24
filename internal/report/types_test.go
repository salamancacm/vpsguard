package report

import (
	"encoding/json"
	"testing"
)

// This specifically covers a real bug: Severity is tagged json:"-", so a
// naive json.Unmarshal into a Finding silently left Severity at its zero
// value (OK) regardless of the finding's real severity — only caught by
// testing internal/fleet against real SSH output, where every remote
// finding displayed as OK. Every consumer that round-trips a Finding
// through JSON (internal/fleet today; possibly others later) depends on
// this working.
func TestFinding_JSONRoundTrip_PreservesSeverity(t *testing.T) {
	tests := []Severity{OK, WARN, CRIT}

	for _, sev := range tests {
		original := NewFinding("ssh", sev, "some message", "some remediation", true)

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal(%v) error: %v", sev, err)
		}

		var roundTripped Finding
		if err := json.Unmarshal(data, &roundTripped); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if roundTripped.Severity != sev {
			t.Errorf("round-tripping a %v finding through JSON produced Severity=%v (data: %s)", sev, roundTripped.Severity, data)
		}
		if roundTripped.Message != original.Message {
			t.Errorf("Message = %q, want %q", roundTripped.Message, original.Message)
		}
	}
}

func TestFinding_JSONRoundTrip_ArraySlice(t *testing.T) {
	// The realistic shape: a []Finding, same as what `vpsguard audit --json`
	// actually emits and internal/fleet actually parses.
	original := []Finding{
		NewFinding("ssh", CRIT, "root login allowed", "", true),
		NewFinding("users", OK, "only root has UID 0", "", false),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var roundTripped []Finding
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if len(roundTripped) != 2 {
		t.Fatalf("got %d findings, want 2", len(roundTripped))
	}
	if roundTripped[0].Severity != CRIT {
		t.Errorf("findings[0].Severity = %v, want CRIT", roundTripped[0].Severity)
	}
	if roundTripped[1].Severity != OK {
		t.Errorf("findings[1].Severity = %v, want OK", roundTripped[1].Severity)
	}
}
