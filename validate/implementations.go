package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultCSPFetcher is the default implementation of CSPFetcher
type DefaultCSPFetcher struct{}

// FetchCSP implements CSPFetcher interface
func (f *DefaultCSPFetcher) FetchCSP(ctx context.Context, client *http.Client, webaddress string, maxBodySize int64, maxRedirects int, logger Logger) (string, string, *url.URL, error) {
	return GetCSPFromWeb(ctx, client, webaddress, maxBodySize, maxRedirects, logger)
}

// DefaultCSPParser is the default implementation of CSPParser
type DefaultCSPParser struct{}

// Parse implements CSPParser interface
func (p *DefaultCSPParser) Parse(policy string, logger Logger, globCache *GlobCache) (Policy, error) {
	return ParsePolicy(policy, logger, globCache)
}

// DefaultHTMLValidator is the default implementation of HTMLValidator
type DefaultHTMLValidator struct{}

// Validate implements HTMLValidator interface
func (v *DefaultHTMLValidator) Validate(policy Policy, page url.URL, html io.Reader) (bool, []Report, error) {
	return ValidatePage(policy, page, html)
}

// DefaultStylesheetValidator is the default implementation of StylesheetValidator
type DefaultStylesheetValidator struct{}

// Validate implements StylesheetValidator interface
func (v *DefaultStylesheetValidator) Validate(policy Policy, page url.URL, css string) (bool, []Report, error) {
	return ValidateStylesheet(policy, page, css)
}

// FileDomainSource reads domains from a file
type FileDomainSource struct {
	FilePath string
}

// GetDomains implements DomainSource interface.
//
// It reads the domains file line by line, trims surrounding whitespace
// (including CR from CRLF files) and skips empty lines. A missing or
// unreadable file is returned as an error instead of being reported as
// "no domains to validate".
func (s *FileDomainSource) GetDomains() ([]string, error) {
	data, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read domains file %s: %w", s.FilePath, err)
	}

	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, nil
}

// LoggerReporter uses a logger to report validation results
type LoggerReporter struct {
	Logger Logger
}

// ReportSuccess implements Reporter interface
func (r *LoggerReporter) ReportSuccess(host string, csp string) {
	r.Logger.Infof("[OK] Validation was successful for %s", host)
	r.Logger.Infof("[OK] Validated policy: %s", csp)
}

// ReportFailure implements Reporter interface
func (r *LoggerReporter) ReportFailure(host string, csp string, reports []Report) {
	r.Logger.Infof("[FAIL] Validation was not successful: %v", reports)
	r.Logger.Infof("[FAIL] Validated policy: %s", csp)
}

// ReportError implements Reporter interface
func (r *LoggerReporter) ReportError(host string, err error) {
	r.Logger.Debugf("Error during validation: %v", err)
	r.Logger.Infof("[ERROR] No response for: %s", host)
}

// ReportMissing implements Reporter interface
func (r *LoggerReporter) ReportMissing(host string) {
	r.Logger.Infof("[MISS] No CSP found for host: %s", host)
}

// NewDefaultCSPFetcher creates a new default CSP fetcher
func NewDefaultCSPFetcher() CSPFetcher {
	return &DefaultCSPFetcher{}
}

// NewDefaultCSPParser creates a new default CSP parser
func NewDefaultCSPParser() CSPParser {
	return &DefaultCSPParser{}
}

// NewDefaultHTMLValidator creates a new default HTML validator
func NewDefaultHTMLValidator() HTMLValidator {
	return &DefaultHTMLValidator{}
}

// NewDefaultStylesheetValidator creates a new default stylesheet validator
func NewDefaultStylesheetValidator() StylesheetValidator {
	return &DefaultStylesheetValidator{}
}

// NewFileDomainSource creates a new file-based domain source
func NewFileDomainSource(baseFolder string) DomainSource {
	return &FileDomainSource{
		FilePath: filepath.Join(baseFolder, "domains_with_ports.txt"),
	}
}

// NewLoggerReporter creates a new logger-based reporter
func NewLoggerReporter(logger Logger) Reporter {
	return &LoggerReporter{Logger: logger}
}
