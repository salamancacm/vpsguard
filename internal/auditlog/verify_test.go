package auditlog

import (
	"testing"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// buildChain constructs a valid, internally-consistent chain of n entries,
// the same way Append would have -- for tests to tamper with afterward.
func buildChain(t *testing.T, n int) []Entry {
	t.Helper()

	var entries []Entry
	prevHash := ""
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		e := Entry{
			Seq:       i,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Findings:  []report.Finding{report.NewFinding("monitor", report.WARN, "test finding", "", false)},
			PrevHash:  prevHash,
		}
		hash, err := hashEntry(e)
		if err != nil {
			t.Fatalf("hashEntry: %v", err)
		}
		e.Hash = hash
		entries = append(entries, e)
		prevHash = hash
	}
	return entries
}

func TestVerifyEntries_EmptyLogIsOK(t *testing.T) {
	result, err := verifyEntries(nil)
	if err != nil {
		t.Fatalf("verifyEntries(nil) error: %v", err)
	}
	if !result.OK || result.EntryCount != 0 {
		t.Errorf("verifyEntries(nil) = %+v, want OK with 0 entries", result)
	}
}

func TestVerifyEntries_IntactChainIsOK(t *testing.T) {
	entries := buildChain(t, 5)

	result, err := verifyEntries(entries)
	if err != nil {
		t.Fatalf("verifyEntries error: %v", err)
	}
	if !result.OK || result.EntryCount != 5 {
		t.Errorf("verifyEntries(intact chain) = %+v, want OK with 5 entries", result)
	}
}

func TestVerifyEntries_EditedFindingsBreaksChain(t *testing.T) {
	entries := buildChain(t, 3)
	entries[1].Findings[0].Message = "tampered message"

	result, err := verifyEntries(entries)
	if err != nil {
		t.Fatalf("verifyEntries error: %v", err)
	}
	if result.OK {
		t.Fatal("verifyEntries should detect an edited entry, got OK")
	}
	if result.BrokenAtSeq != 2 {
		t.Errorf("BrokenAtSeq = %d, want 2 (the tampered entry)", result.BrokenAtSeq)
	}
}

func TestVerifyEntries_DeletedMiddleEntryBreaksChain(t *testing.T) {
	entries := buildChain(t, 3)
	entries = append(entries[:1], entries[2:]...) // delete entry with Seq=2

	result, err := verifyEntries(entries)
	if err != nil {
		t.Fatalf("verifyEntries error: %v", err)
	}
	if result.OK {
		t.Fatal("verifyEntries should detect a deleted entry, got OK")
	}
	if result.BrokenAtSeq != 3 {
		t.Errorf("BrokenAtSeq = %d, want 3 (the entry right after the gap)", result.BrokenAtSeq)
	}
}

func TestVerifyEntries_TruncatedTailIsStillOK(t *testing.T) {
	// Deleting only the most recent entries (not splicing out a middle
	// one) leaves a shorter but still internally-consistent chain --
	// verify can't tell that entries used to exist past what's on disk
	// without an off-host reference to compare against (see Verify's doc
	// comment). This documents that limitation as expected behavior, not
	// a bug.
	entries := buildChain(t, 5)
	entries = entries[:3]

	result, err := verifyEntries(entries)
	if err != nil {
		t.Fatalf("verifyEntries error: %v", err)
	}
	if !result.OK || result.EntryCount != 3 {
		t.Errorf("verifyEntries(truncated tail) = %+v, want OK with 3 entries", result)
	}
}
