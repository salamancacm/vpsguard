package report

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

// Finding is a single result produced by an audit check.
type Finding struct {
	Check       string   `json:"check"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	// Fixable is true when internal/harden has a matching remediation function.
	Fixable bool `json:"fixable"`
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
