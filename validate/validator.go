package validate

import (
	"context"
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
	ErrProjectRequired    = errors.New("project must be specified")
	ErrValidationCanceled = errors.New("validation was canceled")
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
		options:   options,
		logger:    logger,
		globCache: NewGlobCache(),
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

	// Create context for validation operations
	ctx := context.Background()

	err := p.CheckCSPForHosts(ctx)
	if err != nil {
		return err
	}

	p.logger.Infof("Finished validating host HTTP content.")
	return nil
}

func (p *Validator) CheckCSPForHosts(ctx context.Context) error {
	domainsWithPortsFile := filepath.Join(p.options.BaseFolder, "domains_with_ports.txt")
	p.logger.Infof("Using domains with ports input %s", domainsWithPortsFile)

	// Use injected domain source
	domainsWithPorts, err := p.domainSource.GetDomains()
	if err != nil {
		p.logger.Errorf("Error getting domains: %v", err)
		return err
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
		return nil
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
				// Check if context was canceled
				select {
				case <-ctx.Done():
					results <- ValidationResult{
						Host:  url,
						Error: ErrValidationCanceled,
					}
					return
				default:
					result := p.validateHostWithResult(ctx, url)
					results <- result
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, url := range urls {
			select {
			case <-ctx.Done():
				// Context canceled, stop sending jobs
				close(jobs)
				return
			case jobs <- url:
			}
		}
		close(jobs)
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var allResults []ValidationResult
	canceled := false
	for result := range results {
		select {
		case <-ctx.Done():
			canceled = true
		default:
			allResults = append(allResults, result)
			// Still report individual results for real-time feedback
			p.reportResult(result)
		}
	}

	// Generate and log summary
	summary := p.generateSummary(allResults)
	p.logSummary(summary)

	if canceled {
		return ErrValidationCanceled
	}

	return nil
}

func (p *Validator) validateHost(ctx context.Context, host string) {
	p.logger.Infof("Validating host %s", strings.TrimSpace(host))

	// Use injected CSP fetcher
	csp, body, finalHost, err := p.cspFetcher.FetchCSP(ctx, p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects, p.logger)
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
	policy, err := p.cspParser.Parse(csp, p.logger, p.globCache)
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
func (p *Validator) validateHostWithResult(ctx context.Context, host string) ValidationResult {
	p.logger.Infof("Validating host %s", strings.TrimSpace(host))

	result := ValidationResult{
		Host: host,
	}

	// Check if context was canceled before starting
	select {
	case <-ctx.Done():
		result.Error = ErrValidationCanceled
		return result
	default:
	}

	// Use injected CSP fetcher
	csp, body, finalHost, err := p.cspFetcher.FetchCSP(ctx, p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects, p.logger)
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
	policy, err := p.cspParser.Parse(csp, p.logger, p.globCache)
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

// generateSummary creates a ValidationSummary from a slice of ValidationResults
func (p *Validator) generateSummary(results []ValidationResult) ValidationSummary {
	summary := ValidationSummary{
		TotalHosts:    len(results),
		SuccessHosts:  make([]string, 0),
		FailureHosts:  make([]ValidationFailure, 0),
		ErrorHosts:    make([]ValidationError, 0),
		MissingHosts:  make([]string, 0),
		CanceledHosts: make([]string, 0),
	}

	for _, result := range results {
		if result.Error != nil {
			if errors.Is(result.Error, ErrValidationCanceled) {
				summary.CanceledCount++
				summary.CanceledHosts = append(summary.CanceledHosts, result.Host)
			} else {
				summary.ErrorCount++
				summary.ErrorHosts = append(summary.ErrorHosts, ValidationError{
					Host:  result.Host,
					Error: result.Error,
				})
			}
		} else if result.CSP == "" {
			summary.MissingCSPCount++
			summary.MissingHosts = append(summary.MissingHosts, result.Host)
		} else if result.Valid {
			summary.SuccessCount++
			summary.SuccessHosts = append(summary.SuccessHosts, result.Host)
		} else {
			summary.FailureCount++
			summary.FailureHosts = append(summary.FailureHosts, ValidationFailure{
				Host:    result.Host,
				CSP:     result.CSP,
				Reports: result.Reports,
			})
		}
	}

	return summary
}

// logSummary logs a ValidationSummary
func (p *Validator) logSummary(summary ValidationSummary) {
	p.logger.Infof("=" + strings.Repeat("=", 78))
	p.logger.Infof("VALIDATION SUMMARY")
	p.logger.Infof("=" + strings.Repeat("=", 78))
	p.logger.Infof("Total Hosts:       %d", summary.TotalHosts)
	p.logger.Infof("Success:           %d (%.1f%%)", summary.SuccessCount, percentage(summary.SuccessCount, summary.TotalHosts))
	p.logger.Infof("Failures:          %d (%.1f%%)", summary.FailureCount, percentage(summary.FailureCount, summary.TotalHosts))
	p.logger.Infof("Errors:            %d (%.1f%%)", summary.ErrorCount, percentage(summary.ErrorCount, summary.TotalHosts))
	p.logger.Infof("Missing CSP:       %d (%.1f%%)", summary.MissingCSPCount, percentage(summary.MissingCSPCount, summary.TotalHosts))

	if summary.CanceledCount > 0 {
		p.logger.Infof("Canceled:          %d (%.1f%%)", summary.CanceledCount, percentage(summary.CanceledCount, summary.TotalHosts))
	}

	p.logger.Infof("=" + strings.Repeat("=", 78))

	// Log details for failures if verbose mode is enabled
	if p.options.Verbose && len(summary.FailureHosts) > 0 {
		p.logger.Infof("\nFailed Validations (%d):", len(summary.FailureHosts))
		for _, failure := range summary.FailureHosts {
			p.logger.Infof("  - %s: %d violations", failure.Host, len(failure.Reports))
		}
	}

	// Log details for errors if verbose mode is enabled
	if p.options.Verbose && len(summary.ErrorHosts) > 0 {
		p.logger.Infof("\nValidation Errors (%d):", len(summary.ErrorHosts))
		for _, err := range summary.ErrorHosts {
			p.logger.Infof("  - %s: %v", err.Host, err.Error)
		}
	}
}

// percentage calculates the percentage of part out of total
func percentage(part, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return (float64(part) / float64(total)) * 100.0
}
