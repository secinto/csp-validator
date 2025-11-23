package validate

import (
	"crypto/tls"
	"errors"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	utils "secinto/checkfix_utils"
	"strings"
	"sync"
	"time"
)

var (
	defaultSettingsLocation = filepath.Join(os.Getenv("HOME"), ".config/analyzeResponses/settings.yaml")

	// Common errors
	ErrProjectRequired = errors.New("project must be specified")
)

func NewValidator(options *Options) (*Validator, error) {
	return NewValidatorWithDependencies(options, nil, nil, nil, nil, nil, nil)
}

// NewValidatorWithDependencies creates a new Validator with injected dependencies.
// Pass nil for any dependency to use the default implementation.
func NewValidatorWithDependencies(
	options *Options,
	cspFetcher CSPFetcher,
	cspParser CSPParser,
	htmlValidator HTMLValidator,
	stylesheetValidator StylesheetValidator,
	domainSource DomainSource,
	reporter Reporter,
) (*Validator, error) {
	// Create logger instance
	logger := utils.NewLogger()

	validator := &Validator{
		options: options,
		logger:  logger,
	}

	if err := validator.initialize(options.SettingsFile); err != nil {
		return nil, err
	}

	// Inject dependencies or use defaults
	if cspFetcher == nil {
		validator.cspFetcher = NewDefaultCSPFetcher()
	} else {
		validator.cspFetcher = cspFetcher
	}

	if cspParser == nil {
		validator.cspParser = NewDefaultCSPParser()
	} else {
		validator.cspParser = cspParser
	}

	if htmlValidator == nil {
		validator.htmlValidator = NewDefaultHTMLValidator()
	} else {
		validator.htmlValidator = htmlValidator
	}

	if stylesheetValidator == nil {
		validator.stylesheetValidator = NewDefaultStylesheetValidator()
	} else {
		validator.stylesheetValidator = stylesheetValidator
	}

	if domainSource == nil {
		validator.domainSource = NewFileDomainSource(validator.options.BaseFolder)
	} else {
		validator.domainSource = domainSource
	}

	if reporter == nil {
		validator.reporter = NewLoggerReporter(logger)
	} else {
		validator.reporter = reporter
	}

	return validator, nil
}

func (p *Validator) initialize(configLocation string) error {
	config, err := loadConfigFrom(configLocation, p.logger)
	if err != nil {
		return err
	}
	p.config = config

	// Use filepath.Join for proper path handling
	p.options.BaseFolder = filepath.Join(p.config.ProjectsPath, p.options.Project)

	p.config.DpuxFile = strings.Replace(p.config.DpuxFile, "{project_name}", p.options.Project, -1)
	p.config.PortsXMLFile = strings.Replace(p.config.PortsXMLFile, "{project_name}", p.options.Project, -1)

	// Create HTTP client with configurable TLS and timeout settings
	p.httpClient = &http.Client{
		Timeout: time.Duration(p.options.HTTPTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: p.options.InsecureSkipVerify,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return nil
}

func loadConfigFrom(location string, logger Logger) (Config, error) {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			return Config{}, err
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return Config{}, err
	}

	// Set defaults for missing fields
	if config.ProjectsPath == "" {
		config.ProjectsPath = "/checkfix/projects"
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		logger.Warnf("Configuration validation warning: %v", err)
		// Don't fail on validation errors for now, just warn
		// This maintains backward compatibility
	}

	return config, nil
}

//-------------------------------------------
//			Main functions methods
//-------------------------------------------

func (p *Validator) Validate() error {
	p.logger.Infof("Validate HTTP content for project %s", p.options.Project)
	if p.options.Project == "" {
		return ErrProjectRequired
	}

	p.CheckCSPForHosts()
	p.logger.Infof("Finished validating host HTTP content.")
	return nil
}

func (p *Validator) CheckCSPForHosts() {
	domainsWithPortsFile := filepath.Join(p.options.BaseFolder, "domains_with_ports.txt")
	p.logger.Infof("Using domains with ports input %s", domainsWithPortsFile)

	// Use injected domain source
	domainsWithPorts, err := p.domainSource.GetDomains()
	if err != nil {
		p.logger.Errorf("Error getting domains: %v", err)
		return
	}

	// Build list of URLs to validate
	var urls []string
	for _, domainWithPort := range domainsWithPorts {
		if len(domainWithPort) > 0 {
			urls = append(urls, "https://"+domainWithPort)
			urls = append(urls, "http://"+domainWithPort)
		}
	}

	if len(urls) == 0 {
		p.logger.Infof("No domains to validate")
		return
	}

	p.logger.Infof("Validating %d URLs with %d workers", len(urls), p.options.Concurrency)

	// Create worker pool
	jobs := make(chan string, len(urls))
	results := make(chan ValidationResult, len(urls))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < p.options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				result := p.validateHostWithResult(url)
				results <- result
			}
		}()
	}

	// Send jobs
	go func() {
		for _, url := range urls {
			jobs <- url
		}
		close(jobs)
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results as they come in
	for result := range results {
		p.reportResult(result)
	}
}

func (p *Validator) validateHost(host string) {
	p.logger.Infof("Validating host %s", strings.TrimSpace(host))

	// Use injected CSP fetcher
	csp, body, finalHost, err := p.cspFetcher.FetchCSP(p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects, p.logger)
	if err != nil {
		p.reporter.ReportError(host, err)
		return
	}

	// Check if CSP was found
	if len(csp) == 0 {
		p.reporter.ReportMissing(host)
		return
	}

	// Use injected CSP parser
	policy, err := p.cspParser.Parse(csp, p.logger)
	if err != nil {
		p.logger.Errorf("Error during ParsePolicy: %v", err)
		p.reporter.ReportError(host, err)
		return
	}

	// Parse final URL
	page, err := ParseURL(finalHost.String())
	if err != nil {
		p.logger.Errorf("Error parsing URL: %v", err)
		p.reporter.ReportError(host, err)
		return
	}

	// Use injected HTML validator
	valid, reports, err := p.htmlValidator.Validate(policy, *page, strings.NewReader(body))
	if err != nil {
		p.logger.Errorf("Error during validating page: %v", err)
		p.reporter.ReportError(host, err)
		return
	}

	// Use injected reporter
	if valid {
		p.reporter.ReportSuccess(host, csp)
	} else {
		p.reporter.ReportFailure(host, csp, reports)
	}
}

// ParseURL is a helper function that wraps url.Parse
func ParseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}

// validateHostWithResult validates a host and returns a ValidationResult
func (p *Validator) validateHostWithResult(host string) ValidationResult {
	p.logger.Infof("Validating host %s", strings.TrimSpace(host))

	result := ValidationResult{
		Host: host,
	}

	// Use injected CSP fetcher
	csp, body, finalHost, err := p.cspFetcher.FetchCSP(p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects, p.logger)
	if err != nil {
		result.Error = err
		return result
	}

	// Check if CSP was found
	if len(csp) == 0 {
		// No CSP found - not an error, just mark as invalid
		result.Valid = false
		return result
	}

	result.CSP = csp

	// Use injected CSP parser
	policy, err := p.cspParser.Parse(csp, p.logger)
	if err != nil {
		p.logger.Errorf("Error during ParsePolicy: %v", err)
		result.Error = err
		return result
	}

	// Parse final URL
	page, err := ParseURL(finalHost.String())
	if err != nil {
		p.logger.Errorf("Error parsing URL: %v", err)
		result.Error = err
		return result
	}

	// Use injected HTML validator
	valid, reports, err := p.htmlValidator.Validate(policy, *page, strings.NewReader(body))
	if err != nil {
		p.logger.Errorf("Error during validating page: %v", err)
		result.Error = err
		return result
	}

	result.Valid = valid
	result.Reports = reports

	return result
}

// reportResult reports a ValidationResult using the injected reporter
func (p *Validator) reportResult(result ValidationResult) {
	if result.Error != nil {
		p.reporter.ReportError(result.Host, result.Error)
	} else if result.CSP == "" {
		p.reporter.ReportMissing(result.Host)
	} else if result.Valid {
		p.reporter.ReportSuccess(result.Host, result.CSP)
	} else {
		p.reporter.ReportFailure(result.Host, result.CSP, result.Reports)
	}
}
