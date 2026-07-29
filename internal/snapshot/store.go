package snapshot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// StoreDir is where snapshots persist between `vpsguard monitor` runs.
const StoreDir = "/var/lib/vpsguard"

const snapshotFile = "snapshot.json"
const baselineFile = "baseline.json"

// Load reads the last saved snapshot. ok is false if none exists yet
// (e.g. first run of `monitor`).
func Load() (s Snapshot, ok bool, err error) {
	path := filepath.Join(StoreDir, snapshotFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, false, nil
		}
		return Snapshot{}, false, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, false, err
	}
	return s, true, nil
}

// Save persists a snapshot, creating StoreDir if needed.
func Save(s Snapshot) error {
	if err := os.MkdirAll(StoreDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(StoreDir, snapshotFile)
	return os.WriteFile(path, data, 0o600)
}

// LoadBaseline reads the pinned baseline snapshot set by `vpsguard
// baseline`. ok is false if none has been set yet — DiffBaseline is simply
// skipped in that case, same as Load's "no previous snapshot" case.
func LoadBaseline() (s Snapshot, ok bool, err error) {
	path := filepath.Join(StoreDir, baselineFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, false, nil
		}
		return Snapshot{}, false, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, false, err
	}
	return s, true, nil
}

// SaveBaseline persists a snapshot as the trusted reference point for
// DiffBaseline, creating StoreDir if needed. There's only ever one
// baseline — this overwrites any existing one.
func SaveBaseline(s Snapshot) error {
	if err := os.MkdirAll(StoreDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(StoreDir, baselineFile)
	return os.WriteFile(path, data, 0o600)
}
