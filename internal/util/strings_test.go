package util

import "testing"

func TestSlugify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"Mi Aplicación", "mi-aplicacion"},
		{"  Peak   Auth  System  ", "peak-auth-system"},
		{"Hello, World! 123", "hello-world-123"},
		{"Acción & Reacción", "accion-reaccion"},
		{"---leading-and-trailing---", "leading-and-trailing"},
	}

	for _, tt := range tests {
		got := Slugify(tt.input)
		if got != tt.expected {
			t.Errorf("Slugify(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsValidSlug(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"a", false}, // too short (< 2)
		{"mi-app", true},
		{"app-prueba-api", true},
		{"invalid slug with spaces", false},
		{"invalid_slug_with_underscores", false},
		{"-leading-dash", false},
		{"trailing-dash-", false},
		{"double--dash", false},
	}

	for _, tt := range tests {
		got := IsValidSlug(tt.input)
		if got != tt.expected {
			t.Errorf("IsValidSlug(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
