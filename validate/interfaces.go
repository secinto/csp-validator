package validate

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// CSPFetcher defines the interface for fetching CSP policies from web pages
type CSPFetcher interface {
	// FetchCSP retrieves the CSP policy, HTML body, and final URL from a web address
	FetchCSP(ctx context.Context, client *http.Client, webaddress string, maxBodySize int64, maxRedirects int, logger Logger) (csp string, body string, finalURL *url.URL, err error)
}

// CSPParser defines the interface for parsing CSP policy strings
type CSPParser interface {
	// Parse converts a CSP policy string into a Policy object
	Parse(policy string, logger Logger, globCache *GlobCache) (Policy, error)
}

// HTMLValidator defines the interface for validating HTML against CSP policies
type HTMLValidator interface {
	// Validate checks that HTML content passes the specified CSP policy
	Validate(policy Policy, page url.URL, html io.Reader) (valid bool, reports []Report, err error)
}

// StylesheetValidator defines the interface for validating CSS against CSP policies
type StylesheetValidator interface {
	// Validate checks that CSS content passes the specified CSP policy
	Validate(policy Policy, page url.URL, css string) (valid bool, reports []Report, err error)
}

// DomainSource defines the interface for providing domains to validate
type DomainSource interface {
	// GetDomains returns a list of domains to validate
	GetDomains() ([]string, error)
}

// Reporter defines the interface for reporting validation results
type Reporter interface {
	// ReportSuccess reports a successful validation
	ReportSuccess(host string, csp string)

	// ReportFailure reports a failed validation
	ReportFailure(host string, csp string, reports []Report)

	// ReportError reports an error during validation
	ReportError(host string, err error)

	// ReportMissing reports a missing CSP policy
	ReportMissing(host string)
}
