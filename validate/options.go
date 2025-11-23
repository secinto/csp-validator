package validate

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/goflags"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
)

var (
	defaultSettingsLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/analyzeResponses/settings.yaml")
)

type Options struct {
	SettingsFile        string
	Project             string
	BaseFolder          string
	LastModified        bool
	Silent              bool
	Version             bool
	NoColor             bool
	Verbose             bool
	InsecureSkipVerify  bool
	MaxBodySize         int64
	HTTPTimeout         int
	MaxRedirects        int
	Concurrency         int
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{
		MaxBodySize:  10 * 1024 * 1024, // 10MB default
		HTTPTimeout:  10,                // 10 seconds default
		MaxRedirects: 10,                // 10 redirects max
		Concurrency:  10,                // 10 concurrent workers default
	}
	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`get simple findings from the obtained information for the specified project`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.Project, "project", "p", "", "project name for metadata addition"),
		flagSet.StringVarP(&options.SettingsFile, "settings", "s", defaultSettingsLocation, "path to settings YAML file"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.BoolVar(&options.InsecureSkipVerify, "insecure-skip-verify", false, "skip TLS certificate verification (DANGEROUS - use only for testing)"),
		flagSet.IntVar(&options.HTTPTimeout, "timeout", 10, "HTTP request timeout in seconds"),
		flagSet.IntVar(&options.MaxRedirects, "max-redirects", 10, "maximum number of redirects to follow"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 10, "number of concurrent workers"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only results in output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in output"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	options.configureOutput()

	if options.Version {
		fmt.Printf("Current Version: %s\n", VERSION)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		log.Fatalf("Program exiting: %v\n", err)
	}

	return options
}

func (options *Options) configureOutput() {
	if options.Verbose {
		log.SetLevel(logrus.TraceLevel)
	}

	if options.NoColor {
		log.SetFormatter(&logrus.TextFormatter{
			PadLevelText:     true,
			ForceColors:      false,
			DisableTimestamp: true,
		})
	}

	if options.Silent {
		log.SetLevel(logrus.PanicLevel)
	}

	if options.InsecureSkipVerify {
		log.Warnf("WARNING: TLS certificate verification is disabled. This is DANGEROUS and should only be used for testing!")
	}
}

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Validate project name to prevent path traversal
	if options.Project != "" {
		if err := validateProjectName(options.Project); err != nil {
			return err
		}
	}

	return nil
}

// validateProjectName validates project name to prevent path traversal attacks
func validateProjectName(project string) error {
	if project == "" {
		return nil
	}

	// Check for path traversal attempts
	if strings.Contains(project, "..") {
		return errors.New("project name cannot contain '..'")
	}

	// Check for path separators
	if strings.ContainsAny(project, "/\\") {
		return errors.New("project name cannot contain path separators")
	}

	// Check for other dangerous characters
	if strings.ContainsAny(project, "\x00") {
		return errors.New("project name contains invalid characters")
	}

	return nil
}
