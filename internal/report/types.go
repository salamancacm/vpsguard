package report

import "encoding/json"

// Severity indicates how urgent a Finding is.
type Severity int

const (
	OK Severity = iota
	WARN
	CRIT
)

func (s Severity) String() string {
	switch s {
	case OK:
		return "OK"
	case WARN:
		return "WARN"
	case CRIT:
		return "CRIT"
	default:
		return "UNKNOWN"
	}
}

// severityFromString is String's inverse, used when reconstructing a
// Finding from JSON (see Finding.UnmarshalJSON). Unrecognized strings
// default to OK, same as the zero value.
func severityFromString(s string) Severity {
	switch s {
	case "WARN":
		return WARN
	case "CRIT":
		return CRIT
	default:
		return OK
	}
}

// Finding is a single result produced by an audit check.
type Finding struct {
	Check       string   `json:"check"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	// Fixable is true when internal/harden has a matching remediation function.
	Fixable bool `json:"fixable"`
	// Acknowledged is set by internal/config.Config.MarkAccepted when this
	// finding matches an accepted_findings rule. Severity/Message are never
	// altered by acknowledgment — only display/summary treatment changes.
	Acknowledged bool `json:"acknowledged,omitempty"`
	// Beta marks a check whose logic hasn't been validated against the
	// real system/service it's meant to detect (e.g. no real AWS account
	// to test cloud.go's IMDS check against) — only unit-tested and/or
	// validated against the "not applicable" fallback path. Not a
	// judgment on code quality, just an honest signal to weigh a CRIT/WARN
	// from a beta check with a bit more skepticism than a battle-tested one.
	Beta bool `json:"beta,omitempty"`
}

// NewFinding builds a Finding and keeps SeverityStr in sync for JSON output.
func NewFinding(check string, sev Severity, message, remediation string, fixable bool) Finding {
	return Finding{
		Check:       check,
		Severity:    sev,
		SeverityStr: sev.String(),
		Message:     message,
		Remediation: remediation,
		Fixable:     fixable,
	}
}

// NewBetaFinding is NewFinding for a check whose logic is real and tested
// but hasn't been validated against the actual real-world system it
// targets — see Finding.Beta.
func NewBetaFinding(check string, sev Severity, message, remediation string, fixable bool) Finding {
	f := NewFinding(check, sev, message, remediation, fixable)
	f.Beta = true
	return f
}

// UnmarshalJSON reconstructs Severity from SeverityStr. Severity itself is
// tagged json:"-" (Go enums don't round-trip through JSON as human-
// readable text on their own), so without this, unmarshaling a Finding
// from another vpsguard process' --json output — e.g. internal/fleet
// parsing a remote 'vpsguard audit --json' over SSH — would silently
// leave every finding at Severity's zero value (OK), regardless of its
// real severity.
func (f *Finding) UnmarshalJSON(data []byte) error {
	type alias Finding // avoid infinite recursion into this method
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*f = Finding(a)
	f.Severity = severityFromString(f.SeverityStr)
	return nil
}
