package selfupdate

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in                        string
		wantMaj, wantMin, wantPat int
		wantErr                   bool
	}{
		{"v1.2.3", 1, 2, 3, false},
		{"1.2.3", 1, 2, 3, false}, // leading "v" is optional
		{"v0.3.0", 0, 3, 0, false},
		{"dev", 0, 0, 0, true},
		{"v1.2", 0, 0, 0, true},
		{"", 0, 0, 0, true},
	}
	for _, tt := range tests {
		maj, min, pat, err := ParseVersion(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%q) = (%d,%d,%d, nil), want an error", tt.in, maj, min, pat)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%q) returned error: %v", tt.in, err)
			continue
		}
		if maj != tt.wantMaj || min != tt.wantMin || pat != tt.wantPat {
			t.Errorf("ParseVersion(%q) = (%d,%d,%d), want (%d,%d,%d)", tt.in, maj, min, pat, tt.wantMaj, tt.wantMin, tt.wantPat)
		}
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current, latest string
		want            bool
	}{
		{"v0.3.0", "v0.4.0", true},
		{"v0.3.0", "v0.3.1", true},
		{"v0.3.0", "v1.0.0", true},
		{"v0.3.0", "v0.3.0", false}, // equal is not "newer"
		{"v0.4.0", "v0.3.0", false}, // current already ahead
		// The exact lexicographic-vs-numeric trap this needs to avoid:
		// "0.10.0" < "0.3.0" as strings, but 0.10.0 is the newer version.
		{"v0.3.0", "v0.10.0", true},
		{"v0.10.0", "v0.3.0", false},
		{"dev", "v0.3.0", false}, // unparseable current never triggers an update
		{"v0.3.0", "not-a-version", false},
	}
	for _, tt := range tests {
		if got := IsNewer(tt.current, tt.latest); got != tt.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
