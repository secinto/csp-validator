package validate

import (
	"errors"
	"testing"
)

func TestValidator_generateSummary(t *testing.T) {
	// Create a mock validator (we only need the methods, not a full validator)
	v := &Validator{}

	tests := []struct {
		name    string
		results []ValidationResult
		want    ValidationSummary
	}{
		{
			name:    "empty results",
			results: []ValidationResult{},
			want: ValidationSummary{
				TotalHosts:    0,
				SuccessCount:  0,
				FailureCount:  0,
				ErrorCount:    0,
				MissingCSPCount: 0,
				CanceledCount: 0,
				SuccessHosts:  []string{},
				FailureHosts:  []ValidationFailure{},
				ErrorHosts:    []ValidationError{},
				MissingHosts:  []string{},
				CanceledHosts: []string{},
			},
		},
		{
			name: "all successful",
			results: []ValidationResult{
				{Host: "https://example.com", Valid: true, CSP: "default-src 'self'"},
				{Host: "https://test.org", Valid: true, CSP: "default-src 'none'"},
			},
			want: ValidationSummary{
				TotalHosts:   2,
				SuccessCount: 2,
				SuccessHosts: []string{"https://example.com", "https://test.org"},
				FailureHosts:  []ValidationFailure{},
				ErrorHosts:    []ValidationError{},
				MissingHosts:  []string{},
				CanceledHosts: []string{},
			},
		},
		{
			name: "all failures",
			results: []ValidationResult{
				{
					Host:  "https://example.com",
					Valid: false,
					CSP:   "default-src 'self'",
					Reports: []Report{
						{Document: "https://example.com", Blocked: "https://evil.com"},
					},
				},
				{
					Host:  "https://test.org",
					Valid: false,
					CSP:   "default-src 'none'",
					Reports: []Report{
						{Document: "https://test.org", Blocked: "inline-script"},
					},
				},
			},
			want: ValidationSummary{
				TotalHosts:   2,
				FailureCount: 2,
				FailureHosts: []ValidationFailure{
					{
						Host: "https://example.com",
						CSP:  "default-src 'self'",
						Reports: []Report{
							{Document: "https://example.com", Blocked: "https://evil.com"},
						},
					},
					{
						Host: "https://test.org",
						CSP:  "default-src 'none'",
						Reports: []Report{
							{Document: "https://test.org", Blocked: "inline-script"},
						},
					},
				},
				SuccessHosts:  []string{},
				ErrorHosts:    []ValidationError{},
				MissingHosts:  []string{},
				CanceledHosts: []string{},
			},
		},
		{
			name: "all errors",
			results: []ValidationResult{
				{Host: "https://example.com", Error: errors.New("network error")},
				{Host: "https://test.org", Error: errors.New("timeout")},
			},
			want: ValidationSummary{
				TotalHosts: 2,
				ErrorCount: 2,
				ErrorHosts: []ValidationError{
					{Host: "https://example.com", Error: errors.New("network error")},
					{Host: "https://test.org", Error: errors.New("timeout")},
				},
				SuccessHosts:  []string{},
				FailureHosts:  []ValidationFailure{},
				MissingHosts:  []string{},
				CanceledHosts: []string{},
			},
		},
		{
			name: "missing CSP",
			results: []ValidationResult{
				{Host: "https://example.com", Valid: false, CSP: ""},
				{Host: "https://test.org", Valid: false, CSP: ""},
			},
			want: ValidationSummary{
				TotalHosts:      2,
				MissingCSPCount: 2,
				MissingHosts:    []string{"https://example.com", "https://test.org"},
				SuccessHosts:    []string{},
				FailureHosts:    []ValidationFailure{},
				ErrorHosts:      []ValidationError{},
				CanceledHosts:   []string{},
			},
		},
		{
			name: "canceled validations",
			results: []ValidationResult{
				{Host: "https://example.com", Error: ErrValidationCanceled},
				{Host: "https://test.org", Error: ErrValidationCanceled},
			},
			want: ValidationSummary{
				TotalHosts:    2,
				CanceledCount: 2,
				CanceledHosts: []string{"https://example.com", "https://test.org"},
				SuccessHosts:  []string{},
				FailureHosts:  []ValidationFailure{},
				ErrorHosts:    []ValidationError{},
				MissingHosts:  []string{},
			},
		},
		{
			name: "mixed results",
			results: []ValidationResult{
				{Host: "https://success.com", Valid: true, CSP: "default-src 'self'"},
				{
					Host:    "https://failure.com",
					Valid:   false,
					CSP:     "default-src 'none'",
					Reports: []Report{{Blocked: "script"}},
				},
				{Host: "https://error.com", Error: errors.New("network error")},
				{Host: "https://missing.com", Valid: false, CSP: ""},
				{Host: "https://canceled.com", Error: ErrValidationCanceled},
			},
			want: ValidationSummary{
				TotalHosts:      5,
				SuccessCount:    1,
				FailureCount:    1,
				ErrorCount:      1,
				MissingCSPCount: 1,
				CanceledCount:   1,
				SuccessHosts:    []string{"https://success.com"},
				FailureHosts: []ValidationFailure{
					{
						Host:    "https://failure.com",
						CSP:     "default-src 'none'",
						Reports: []Report{{Blocked: "script"}},
					},
				},
				ErrorHosts: []ValidationError{
					{Host: "https://error.com", Error: errors.New("network error")},
				},
				MissingHosts:  []string{"https://missing.com"},
				CanceledHosts: []string{"https://canceled.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.generateSummary(tt.results)

			// Check counts
			if got.TotalHosts != tt.want.TotalHosts {
				t.Errorf("TotalHosts = %d; want %d", got.TotalHosts, tt.want.TotalHosts)
			}
			if got.SuccessCount != tt.want.SuccessCount {
				t.Errorf("SuccessCount = %d; want %d", got.SuccessCount, tt.want.SuccessCount)
			}
			if got.FailureCount != tt.want.FailureCount {
				t.Errorf("FailureCount = %d; want %d", got.FailureCount, tt.want.FailureCount)
			}
			if got.ErrorCount != tt.want.ErrorCount {
				t.Errorf("ErrorCount = %d; want %d", got.ErrorCount, tt.want.ErrorCount)
			}
			if got.MissingCSPCount != tt.want.MissingCSPCount {
				t.Errorf("MissingCSPCount = %d; want %d", got.MissingCSPCount, tt.want.MissingCSPCount)
			}
			if got.CanceledCount != tt.want.CanceledCount {
				t.Errorf("CanceledCount = %d; want %d", got.CanceledCount, tt.want.CanceledCount)
			}

			// Check list lengths
			if len(got.SuccessHosts) != len(tt.want.SuccessHosts) {
				t.Errorf("len(SuccessHosts) = %d; want %d", len(got.SuccessHosts), len(tt.want.SuccessHosts))
			}
			if len(got.FailureHosts) != len(tt.want.FailureHosts) {
				t.Errorf("len(FailureHosts) = %d; want %d", len(got.FailureHosts), len(tt.want.FailureHosts))
			}
			if len(got.ErrorHosts) != len(tt.want.ErrorHosts) {
				t.Errorf("len(ErrorHosts) = %d; want %d", len(got.ErrorHosts), len(tt.want.ErrorHosts))
			}
			if len(got.MissingHosts) != len(tt.want.MissingHosts) {
				t.Errorf("len(MissingHosts) = %d; want %d", len(got.MissingHosts), len(tt.want.MissingHosts))
			}
			if len(got.CanceledHosts) != len(tt.want.CanceledHosts) {
				t.Errorf("len(CanceledHosts) = %d; want %d", len(got.CanceledHosts), len(tt.want.CanceledHosts))
			}
		})
	}
}

func TestPercentage(t *testing.T) {
	tests := []struct {
		name  string
		part  int
		total int
		want  float64
	}{
		{
			name:  "zero total",
			part:  10,
			total: 0,
			want:  0.0,
		},
		{
			name:  "zero part",
			part:  0,
			total: 100,
			want:  0.0,
		},
		{
			name:  "50 percent",
			part:  50,
			total: 100,
			want:  50.0,
		},
		{
			name:  "100 percent",
			part:  100,
			total: 100,
			want:  100.0,
		},
		{
			name:  "33.33 percent",
			part:  1,
			total: 3,
			want:  33.33333333333333,
		},
		{
			name:  "75 percent",
			part:  3,
			total: 4,
			want:  75.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentage(tt.part, tt.total)
			if got != tt.want {
				t.Errorf("percentage(%d, %d) = %f; want %f", tt.part, tt.total, got, tt.want)
			}
		})
	}
}

func TestValidator_logSummary(t *testing.T) {
	// Create a validator with a mock logger
	logger := &mockLogger{}
	v := &Validator{
		logger: logger,
		options: &Options{
			Verbose: false,
		},
	}

	summary := ValidationSummary{
		TotalHosts:      10,
		SuccessCount:    6,
		FailureCount:    2,
		ErrorCount:      1,
		MissingCSPCount: 1,
		CanceledCount:   0,
	}

	// This should not panic
	v.logSummary(summary)

	// Test with verbose mode
	v.options.Verbose = true
	summary.FailureHosts = []ValidationFailure{
		{Host: "https://fail1.com", Reports: []Report{{}, {}}},
	}
	summary.ErrorHosts = []ValidationError{
		{Host: "https://error1.com", Error: errors.New("test error")},
	}

	// This should also not panic
	v.logSummary(summary)
}

func TestValidator_logSummary_WithCanceled(t *testing.T) {
	logger := &mockLogger{}
	v := &Validator{
		logger: logger,
		options: &Options{
			Verbose: false,
		},
	}

	summary := ValidationSummary{
		TotalHosts:    5,
		SuccessCount:  2,
		CanceledCount: 3,
		CanceledHosts: []string{"https://c1.com", "https://c2.com", "https://c3.com"},
	}

	// Should not panic and should log canceled count
	v.logSummary(summary)
}
