package validate

import (
	"crypto/tls"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	utils "secinto/checkfix_utils"
	"strings"
	"time"
)

var (
	log       = utils.NewLogger()
	appConfig Config
)

func NewValidator(options *Options) (*Validator, error) {
	finder := &Validator{options: options}
	finder.initialize(options.SettingsFile)
	return finder, nil
}

func (p *Validator) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)

	// Use filepath.Join for proper path handling
	p.options.BaseFolder = filepath.Join(appConfig.ProjectsPath, p.options.Project)

	appConfig.DpuxFile = strings.Replace(appConfig.DpuxFile, "{project_name}", p.options.Project, -1)
	appConfig.PortsXMLFile = strings.Replace(appConfig.PortsXMLFile, "{project_name}", p.options.Project, -1)

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
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	// Set defaults for missing fields
	if config.ProjectsPath == "" {
		config.ProjectsPath = "/checkfix/projects"
	}

	return config
}

//-------------------------------------------
//			Main functions methods
//-------------------------------------------

func (p *Validator) Validate() error {
	log.Infof("Validate HTTP content for project %s", p.options.Project)
	if p.options.Project != "" {
		p.CheckCSPForHosts()
		log.Infof("Finished validating host HTTP content.")
	} else {
		log.Fatal("Project must be specified")
	}
	return nil
}

func (p *Validator) CheckCSPForHosts() {
	domainsWithPortsFile := filepath.Join(p.options.BaseFolder, "domains_with_ports.txt")
	log.Infof("Using domains with ports input %s", domainsWithPortsFile)
	domainsWithPorts := utils.ReadPlainTextFileByLines(domainsWithPortsFile)
	for _, domainWithPort := range domainsWithPorts {
		if len(domainWithPort) > 0 {
			p.validateHost("https://" + domainWithPort)
			p.validateHost("http://" + domainWithPort)
		}
	}
}

func (p *Validator) validateHost(host string) {
	log.Infof("Validating host %s", strings.TrimSpace(host))
	csp, body, finalHost, err := GetCSPFromWeb(p.httpClient, host, p.options.MaxBodySize, p.options.MaxRedirects)
	if err != nil {
		log.Debugf("Error during GetCSPFromWeb: %v", err)
		log.Infof("[ERROR] No response for: %s", host)
	} else {
		if len(csp) > 0 {
			policy, err := ParsePolicy(csp)
			if err != nil {
				log.Errorf("Error during ParsePolicy: %v", err)
			}
			page, err := ParseURL(finalHost.String())
			if err != nil {
				log.Errorf("Error parsing URL: %v", err)
			}

			valid, reports, err := ValidatePage(policy, *page, strings.NewReader(body))
			if err != nil {
				log.Errorf("Error during validating page: %v", err)
			}
			if valid {
				log.Infof("[OK] Validation was successful for %s", host)
				log.Infof("[OK] Validated policy: %s", csp)
			} else {
				log.Infof("[FAIL] Validation was not successful: %v", reports)
				log.Infof("[FAIL] Validated policy: %s", csp)
			}
		} else {
			log.Infof("[MISS] No CSP found for host: %s", host)
		}
	}

}

// ParseURL is a helper function that wraps url.Parse
func ParseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}
