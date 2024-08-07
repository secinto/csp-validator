package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/secinto/csp-validator/validate"
)

func main() {
	// Parse the command line flags and read config files
	options := validate.ParseOptions()

	validator, err := validate.NewValidator(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create csp-validator: %s\n", err)
	}

	err = validator.Validate()
	if err != nil {
		gologger.Fatal().Msgf("Could not validate CSP policies: %s\n", err)
	}
}
