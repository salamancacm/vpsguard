package snapshot

import "testing"

func TestWatchedBinaryCount(t *testing.T) {
	tests := []struct {
		name string
		s    Snapshot
		want int
	}{
		{
			name: "no binaries hashed",
			s:    Snapshot{BinaryHashes: map[string]string{}},
			want: 0,
		},
		{
			name: "some watched binaries present, plus vpsguard's own executable",
			s: Snapshot{BinaryHashes: map[string]string{
				"/usr/sbin/sshd":          "aaaa",
				"/bin/su":                 "bbbb",
				"/usr/local/bin/vpsguard": "cccc", // not a watched binary
			}},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WatchedBinaryCount(tt.s); got != tt.want {
				t.Errorf("WatchedBinaryCount(%v) = %d, want %d", tt.s, got, tt.want)
			}
		})
	}
}
