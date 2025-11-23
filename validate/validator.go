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
	"time"
)

var (
	defaultSettingsLocation = filepath.Join(os.Getenv("HOME"), ".config/analyzeResponses/settings.yaml")

	// Common errors
	ErrProjectRequired = errors.New("project must be specified")
)

func NewValidator(options *Options) (*Validator, error) {
	// Create logger instance
	logger := utils.NewLogger()

	validator := &Validator{
		options: options,
		logger:  logger,
	}

	if err := validator.initialize(options.SettingsFile); err != nil {
		return nil, err
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
	domainsWithPorts := utils.ReadPlainTextFileByLines(domainsWithPortsFile)
	for _, domainWithPort := range domainsWithPorts {
		if len(domainWithPort) > 0 {
			p.validateHost("https://" + domainWithPort)
			p.validateHost("http://" + domainWithPort)
		}
	}
}

func (p *Validator) validateHost(host string) {
	p.logger.Infof("Validating host %s", strings.TrimSpace(host))
	csp, body, finalHost, err := GetCSPFromWeb(p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects, p.logger)
	if err != nil {
		p.logger.Debugf("Error during GetCSPFromWeb: %v", err)
		p.logger.Infof("[ERROR] No response for: %s", host)
	} else {
		if len(csp) > 0 {
			policy, err := ParsePolicy(csp, p.logger)
			if err != nil {
				p.logger.Errorf("Error during ParsePolicy: %v", err)
			}
			page, err := ParseURL(finalHost.String())
			if err != nil {
				p.logger.Errorf("Error parsing URL: %v", err)
			}

			valid, reports, err := ValidatePage(policy, *page, strings.NewReader(body))
			if err != nil {
				p.logger.Errorf("Error during validating page: %v", err)
			}
			if valid {
				p.logger.Infof("[OK] Validation was successful for %s", host)
				p.logger.Infof("[OK] Validated policy: %s", csp)
			} else {
				p.logger.Infof("[FAIL] Validation was not successful: %v", reports)
				p.logger.Infof("[FAIL] Validated policy: %s", csp)
			}
		} else {
			p.logger.Infof("[MISS] No CSP found for host: %s", host)
		}
	}

}

// ParseURL is a helper function that wraps url.Parse
func ParseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}
