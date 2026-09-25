package main

import (
	"github.com/secinto/csp-validator/validate"
)

func main() {
	logger := validate.NewLogger()

	// Parse the command line flags and read config files
	options := validate.ParseOptions()

	validator, err := validate.NewValidator(options)
	if err != nil {
		logger.Fatalf("Could not create csp-validator: %s\n", err)
	}

	err = validator.Validate()
	if err != nil {
		logger.Fatalf("Could not validate CSP policies: %s\n", err)
	}
}
