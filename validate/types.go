package validate

import (
	"errors"
	"github.com/gobwas/glob"
	"hash"
	"net/http"
	"net/url"
	"os"
)

const VERSION = "0.1.0"

// Configuration validation errors
var (
	ErrInvalidProjectsPath  = errors.New("projects_path is empty or invalid")
	ErrProjectsPathNotExist = errors.New("projects_path directory does not exist")
)

type Config struct {
	ProjectsPath     string `yaml:"projects_path,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DpuxXMLFile      string `yaml:"dpux_xml,omitempty"`
	DpuxIPFile       string `yaml:"dpux_ip,omitempty"`
	HostMappingFile  string `yaml:"host_mapping_file,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	HttpxIPSFile     string `yaml:"httpx_ips,omitempty"`
	HttpxCleanFile   string `yaml:"httpx_clean,omitempty"`
	PortsXMLFile     string `yaml:"ports_xml,omitempty"`
	PortsSimpleFile  string `yaml:"ports_simple,omitempty"`
}

// Validate checks if the configuration is valid
func (c Config) Validate() error {
	// Check that ProjectsPath is not empty
	if c.ProjectsPath == "" {
		return ErrInvalidProjectsPath
	}

	// Check if the projects path exists
	if info, err := os.Stat(c.ProjectsPath); err != nil {
		if os.IsNotExist(err) {
			return ErrProjectsPathNotExist
		}
		return err
	} else if !info.IsDir() {
		return errors.New("projects_path is not a directory")
	}

	return nil
}

type Validator struct {
	options    *Options
	config     Config
	httpClient *http.Client
	logger     Logger
	globCache  *GlobCache

	// Dependencies (injected)
	cspFetcher          CSPFetcher
	cspParser           CSPParser
	htmlValidator       HTMLValidator
	stylesheetValidator StylesheetValidator
	domainSource        DomainSource
	reporter            Reporter
}

// Logger interface for dependency injection
type Logger interface {
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	SetLevel(level interface{})
	SetFormatter(formatter interface{})
}

// Policy represents the entire CSP policy and its directives.
type Policy struct {
	Directives              map[string]Directive
	UpgradeInsecureRequests bool
	BlockAllMixedContent    bool
}

// SourceDirective is used to enforce a CSP source policy on a URL.
type SourceDirective struct {
	ruleCount int

	None         bool
	Nonces       map[string]bool
	Hashes       []HashSource
	UnsafeEval   bool
	UnsafeInline bool
	Self         bool
	Schemes      map[string]bool
	Hosts        []glob.Glob
	SrcHosts     []string
}

// SourceContext is the context required by a CSP policy.
type SourceContext struct {
	URL          url.URL
	Page         url.URL
	UnsafeInline bool
	UnsafeEval   bool
	Nonce        string
	Body         []byte
}

// HashSource is a SourceDirective rule that matches the hash of content.
type HashSource struct {
	Algorithm func() hash.Hash
	Value     string
}

// Report contains information about a CSP violation.
type Report struct {
	Document      string
	Blocked       string
	DirectiveName string
	Directive     Directive
	Context       SourceContext
}

// ValidationResult contains the result of validating a single host.
// It is returned by the validateHostWithResult method and collected
// for aggregation into ValidationSummary.
type ValidationResult struct {
	Host    string   // The URL that was validated
	Valid   bool     // Whether the CSP policy allows all resources on the page
	CSP     string   // The CSP policy string that was validated
	Reports []Report // Detailed violation reports if validation failed
	Error   error    // Any error encountered during validation
}

// ValidationSummary contains aggregated validation results and statistics
// from a batch validation run. It provides counts and detailed breakdowns
// of successes, failures, errors, and missing CSP policies.
//
// The summary is generated after all validations complete and includes
// percentage calculations for easy interpretation of results.
type ValidationSummary struct {
	TotalHosts      int                 // Total number of hosts validated
	SuccessCount    int                 // Number of hosts that passed validation
	FailureCount    int                 // Number of hosts that failed validation
	ErrorCount      int                 // Number of hosts that encountered errors
	MissingCSPCount int                 // Number of hosts without CSP policies
	CanceledCount   int                 // Number of validations canceled
	SuccessHosts    []string            // List of successful hosts
	FailureHosts    []ValidationFailure // Detailed failure information
	ErrorHosts      []ValidationError   // Detailed error information
	MissingHosts    []string            // List of hosts without CSP
	CanceledHosts   []string            // List of canceled validations
}

// ValidationFailure represents a host that failed CSP validation.
// It contains the failing host, its CSP policy, and detailed reports
// about which resources violated the policy.
type ValidationFailure struct {
	Host    string   // The URL that failed validation
	CSP     string   // The CSP policy that was violated
	Reports []Report // Detailed violation reports
}

// ValidationError represents a host that encountered an error during validation.
// Errors are distinct from validation failures - they indicate that the
// validation process itself failed (e.g., network errors, parse errors).
type ValidationError struct {
	Host  string // The URL where the error occurred
	Error error  // The error that occurred
}
