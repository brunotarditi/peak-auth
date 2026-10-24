package util

import (
	"html/template"
	"testing"
)

func TestSanitizeSafeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected template.URL
	}{
		{
			name:     "empty string returns empty",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace returns empty",
			input:    "   ",
			expected: "",
		},
		{
			name:     "relative path allowed",
			input:    "/static/img/logo.png",
			expected: "/static/img/logo.png",
		},
		{
			name:     "protocol relative blocked",
			input:    "//evil.com/xss",
			expected: "#",
		},
		{
			name:     "https allowed",
			input:    "https://example.com/logo.png",
			expected: "https://example.com/logo.png",
		},
		{
			name:     "http allowed",
			input:    "http://example.com/logo.png",
			expected: "http://example.com/logo.png",
		},
		{
			name:     "data image allowed",
			input:    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
			expected: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
		},
		{
			name:     "mailto allowed",
			input:    "mailto:support@peakauth.com",
			expected: "mailto:support@peakauth.com",
		},
		{
			name:     "javascript scheme blocked",
			input:    "javascript:alert(1)",
			expected: "#",
		},
		{
			name:     "data text html blocked",
			input:    "data:text/html,<script>alert(1)</script>",
			expected: "#",
		},
		{
			name:     "vbscript scheme blocked",
			input:    "vbscript:msgbox(1)",
			expected: "#",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeSafeURL(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeSafeURL(%q) = %q, expected %q", tt.input, got, tt.expected)
			}
		})
	}
}
