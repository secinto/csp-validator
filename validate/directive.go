package validate

// Directive is a rule for a CSP directive.
type Directive interface {
	// Check the context and return whether or not it's allowed.
	Check(Policy, SourceContext) (bool, error)
}

// AllowDirective always allows access to the context.
type AllowDirective struct{}

// Check implements Directive.
func (AllowDirective) Check(Policy, SourceContext) (bool, error) {
	return true, nil
}
