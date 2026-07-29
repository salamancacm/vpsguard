// Package auditlog keeps a tamper-evident, append-only history of every
// `vpsguard monitor` run's findings.
//
// A compromised host can always delete files -- there's no way to stop
// that from inside the host itself. What this package provides instead is
// tamper *evidence*: each entry embeds the hash of the entry before it, so
// deleting or editing any entry (including the most recent one) breaks the
// chain for everything after the tampered point, and 'vpsguard auditlog
// verify' will say exactly where. An operator who keeps even one honest
// copy of a past entry's hash off-host (in a notification, a paste, a
// second server) can detect a full log replacement, not just an in-place
// edit.
package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// StoreDir is where the audit log persists, alongside monitor's snapshots.
const StoreDir = "/var/lib/vpsguard"

const logFile = "audit.log"

// Entry is one line of the audit log: one `monitor` run's findings, plus
// the chain linkage that makes tampering detectable.
type Entry struct {
	Seq       int              `json:"seq"`
	Timestamp time.Time        `json:"timestamp"`
	Findings  []report.Finding `json:"findings"`
	// PrevHash is the previous entry's Hash, or "" for the first entry
	// ever written (the chain's genesis).
	PrevHash string `json:"prev_hash"`
	// Hash covers Seq, Timestamp, Findings, and PrevHash -- see hashEntry.
	Hash string `json:"hash"`
}

// Path returns the audit log's on-disk location.
func Path() string {
	return filepath.Join(StoreDir, logFile)
}

// Append adds one entry to the log for this monitor run's findings,
// chained to whatever entry (if any) was written last. Creates the log
// (and StoreDir) if this is the first run. The file is only ever opened
// for appending -- vpsguard itself never truncates, rewrites, or deletes
// log lines.
func Append(findings []report.Finding) (Entry, error) {
	if err := os.MkdirAll(StoreDir, 0o700); err != nil {
		return Entry{}, err
	}

	entries, err := Load()
	if err != nil {
		return Entry{}, fmt.Errorf("reading existing log to chain the next entry: %w", err)
	}

	seq := 1
	prevHash := ""
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		seq = last.Seq + 1
		prevHash = last.Hash
	}

	e := Entry{
		Seq:       seq,
		Timestamp: time.Now().UTC(),
		Findings:  findings,
		PrevHash:  prevHash,
	}
	hash, err := hashEntry(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = hash

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}

	f, err := os.OpenFile(Path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Load reads every entry in the audit log, in order. A missing file
// returns an empty slice, not an error -- same as no monitor run having
// happened yet.
func Load() ([]Entry, error) {
	f, err := os.Open(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // findings lists are small, but be generous
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("parsing audit log line %d: %w", len(entries)+1, err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// hashEntry computes the chained hash for an entry: sha256 of its Seq,
// Timestamp, Findings (as canonical JSON), and PrevHash. Changing any of
// those -- including which entry it claims to follow -- changes the hash.
func hashEntry(e Entry) (string, error) {
	findingsJSON, err := json.Marshal(e.Findings)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s", e.Seq, e.Timestamp.Format(time.RFC3339Nano), findingsJSON, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil)), nil
}
