package checks

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestCloudMetadataFinding_IMDSv1Accessible(t *testing.T) {
	// Simulates AWS EC2 with HttpTokens=optional: an unauthenticated GET
	// succeeds — this is the real vulnerability the check exists to catch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ami-id\nhostname\ninstance-id\n"))
	}))
	defer srv.Close()

	got := cloudMetadataFinding(srv.Client(), srv.URL)
	if got.Severity != report.CRIT {
		t.Errorf("Severity = %v, want CRIT (IMDSv1 accessible unauthenticated)", got.Severity)
	}
}

func TestCloudMetadataFinding_IMDSv2Enforced(t *testing.T) {
	// Simulates AWS EC2 with HttpTokens=required: a request without the
	// IMDSv2 token header gets a real 401 from the metadata service.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	got := cloudMetadataFinding(srv.Client(), srv.URL)
	if got.Severity != report.OK {
		t.Errorf("Severity = %v, want OK (IMDSv2 enforced)", got.Severity)
	}
}

func TestCloudMetadataFinding_NotAWS(t *testing.T) {
	// A different cloud's metadata service (or anything else) responding
	// with something other than 200/401 must not be misread as either
	// "vulnerable" or "IMDSv2 enforced" — it's simply not this check's
	// business.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := cloudMetadataFinding(srv.Client(), srv.URL)
	if got.Severity != report.OK {
		t.Errorf("Severity = %v, want OK (not an AWS IMDS response)", got.Severity)
	}
}

func TestCloudMetadataFinding_Unreachable(t *testing.T) {
	// The common case off AWS entirely: nothing listens on the target at
	// all, so the request errors out (connection refused/timeout) rather
	// than returning any HTTP status.
	client := &http.Client{Timeout: 500 * time.Millisecond}
	got := cloudMetadataFinding(client, "http://127.0.0.1:1") // port 0 reserved, always refused

	if got.Severity != report.OK {
		t.Errorf("Severity = %v, want OK (unreachable)", got.Severity)
	}
}
