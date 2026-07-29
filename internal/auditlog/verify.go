package auditlog

import "fmt"

// VerifyResult is the outcome of checking the audit log's hash chain.
type VerifyResult struct {
	OK bool
	// EntryCount is how many entries were checked.
	EntryCount int
	// BrokenAtSeq is the Seq of the first entry that fails verification
	// (hash mismatch, broken chain linkage, or an out-of-order Seq). Zero
	// when OK is true.
	BrokenAtSeq int
	// Reason describes what's wrong at BrokenAtSeq. Empty when OK is true.
	Reason string
}

// Verify recomputes the audit log's hash chain from scratch and reports
// whether it's intact. Any edit, deletion, or reordering of a past entry
// -- including the most recent one -- breaks the chain from that point on,
// which is exactly what this catches; it cannot, by itself, catch a wholesale
// replacement of the entire log by an attacker with root, since that
// attacker can just regenerate a new, internally-consistent chain from
// entry 1. Comparing the last known Hash against a copy kept off-host (e.g.
// one you saved from a past 'vpsguard auditlog verify' run, or from a
// notification) is the only way to catch that.
func Verify() (VerifyResult, error) {
	entries, err := Load()
	if err != nil {
		return VerifyResult{}, err
	}
	return verifyEntries(entries)
}

// verifyEntries is Verify's chain-checking logic, split out from the file
// read so it's testable without touching disk.
func verifyEntries(entries []Entry) (VerifyResult, error) {
	prevHash := ""
	wantSeq := 1
	for _, e := range entries {
		if e.Seq != wantSeq {
			return VerifyResult{OK: false, EntryCount: len(entries), BrokenAtSeq: e.Seq,
				Reason: fmt.Sprintf("expected seq %d, found %d", wantSeq, e.Seq)}, nil
		}
		if e.PrevHash != prevHash {
			return VerifyResult{OK: false, EntryCount: len(entries), BrokenAtSeq: e.Seq,
				Reason: "prev_hash doesn't match the preceding entry's hash"}, nil
		}

		wantHash, err := hashEntry(e)
		if err != nil {
			return VerifyResult{}, err
		}
		if e.Hash != wantHash {
			return VerifyResult{OK: false, EntryCount: len(entries), BrokenAtSeq: e.Seq,
				Reason: "hash doesn't match this entry's own content"}, nil
		}

		prevHash = e.Hash
		wantSeq++
	}

	return VerifyResult{OK: true, EntryCount: len(entries)}, nil
}
