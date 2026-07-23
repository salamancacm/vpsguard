package report

import (
	"encoding/json"
	"io"
)

// PrintJSON writes findings as a JSON array.
func PrintJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
