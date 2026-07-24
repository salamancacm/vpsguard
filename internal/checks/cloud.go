package checks

import (
	"net/http"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// awsMetadataURL is AWS EC2's instance metadata service endpoint. It's a
// fixed, well-known link-local address (not user input), so querying it
// carries none of the risk an SSRF-style outbound request normally would.
const awsMetadataURL = "http://169.254.169.254/latest/meta-data/"

// CloudMetadata checks for AWS EC2's classic SSRF exposure: an instance
// metadata service (IMDS) that still accepts unauthenticated, IMDSv1-style
// requests — the vector behind real breaches like Capital One's 2019
// incident. Needs no AWS credentials or SDK, only network access to the
// metadata endpoint from inside the instance, matching every other check
// in this package. Silently a no-op (OK) on anything that isn't an AWS
// EC2 instance with IMDSv1 disabled — including other clouds that also
// use 169.254.169.254 (GCP, Azure, ...) but a different API shape.
func CloudMetadata() []report.Finding {
	client := &http.Client{Timeout: 2 * time.Second}
	return []report.Finding{cloudMetadataFinding(client, awsMetadataURL)}
}

// cloudMetadataFinding is the testable core: given an HTTP client and
// target URL, classify the response. Split out so tests can point it at a
// local httptest.Server instead of the real metadata endpoint.
func cloudMetadataFinding(client *http.Client, url string) report.Finding {
	const check = "cloud"

	resp, err := client.Get(url)
	if err != nil {
		return report.NewFinding(check, report.OK,
			"not running on AWS EC2 (or the instance metadata service is unreachable)", "", false)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return report.NewFinding(check, report.CRIT,
			"AWS EC2 instance metadata service (IMDS) accepts unauthenticated requests — IMDSv1 is allowed",
			"require IMDSv2 from a machine with AWS credentials: 'aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required' (an EC2 API setting vpsguard can't change from inside the instance)", false)
	case http.StatusUnauthorized:
		return report.NewFinding(check, report.OK,
			"AWS EC2 instance metadata service requires IMDSv2 (token-based) requests", "", false)
	default:
		return report.NewFinding(check, report.OK,
			"not running on AWS EC2 (or the instance metadata service is unreachable)", "", false)
	}
}
