package validate

import (
	"github.com/gobwas/glob"
	"hash"
	"net/url"
)

const VERSION = "0.1.0"

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

type Validator struct {
	options *Options
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
