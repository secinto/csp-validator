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
	ErrInvalidProjectsPath = errors.New("projects_path is empty or invalid")
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
