package selfupdate

import "testing"

func TestExtractChecksum(t *testing.T) {
	checksums := `be44f5b5968cada16a23b67ccf10989a4f130f8958d758e0a8cb41aec2d02307  vpsguard-linux-amd64
de6e301123787b8b017a864e34d33116c6559b3c992cd11733b2d859a72a9615  vpsguard-linux-arm64
9f8a2b1c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a  checksums-of-checksums`

	got, err := extractChecksum(checksums, "vpsguard-linux-amd64")
	if err != nil {
		t.Fatalf("extractChecksum() error: %v", err)
	}
	want := "be44f5b5968cada16a23b67ccf10989a4f130f8958d758e0a8cb41aec2d02307"
	if got != want {
		t.Errorf("extractChecksum() = %q, want %q", got, want)
	}
}

func TestExtractChecksum_NotFound(t *testing.T) {
	checksums := "be44f5b5968cada16a23b67ccf10989a4f130f8958d758e0a8cb41aec2d02307  vpsguard-linux-amd64"

	if _, err := extractChecksum(checksums, "vpsguard-linux-arm64"); err == nil {
		t.Error("extractChecksum() for a missing asset should return an error")
	}
}

func TestExtractChecksum_EmptyInput(t *testing.T) {
	if _, err := extractChecksum("", "vpsguard-linux-amd64"); err == nil {
		t.Error("extractChecksum() on empty input should return an error")
	}
}
