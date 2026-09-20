package util

import (
	"strings"
	"testing"
)

func TestValidatePasswordLength(t *testing.T) {
	if err := ValidatePasswordLength("corta"); err != nil {
		t.Fatalf("password corta no debería fallar: %v", err)
	}
	exact := make([]byte, 72)
	for i := range exact {
		exact[i] = 'a'
	}
	if err := ValidatePasswordLength(string(exact)); err != nil {
		t.Fatalf("72 bytes debería ser válido: %v", err)
	}
	long := append(exact, 'a')
	if err := ValidatePasswordLength(string(long)); err == nil {
		t.Fatal("73 bytes debería exceder el límite de bcrypt")
	}
}

func TestValidateMinimumPasswordPolicy(t *testing.T) {
	// Test length requirement
	if err := ValidateMinimumPasswordPolicy("1234567"); err == nil {
		t.Fatal("password con menos de 8 caracteres debería fallar")
	}

	// Test that simple 8-character password without complexity fails
	if err := ValidateMinimumPasswordPolicy("12345678"); err == nil {
		t.Fatal("password sin complejidad debería fallar")
	}

	// Test missing uppercase
	if err := ValidateMinimumPasswordPolicy("abc123!@"); err == nil {
		t.Fatal("password sin mayúscula debería fallar")
	}

	// Test missing number
	if err := ValidateMinimumPasswordPolicy("Abcdefg!"); err == nil {
		t.Fatal("password sin dígito debería fallar")
	}

	// Test missing symbol
	if err := ValidateMinimumPasswordPolicy("Abcd1234"); err == nil {
		t.Fatal("password sin símbolo debería fallar")
	}

	// Test valid password with all requirements
	if err := ValidateMinimumPasswordPolicy("Abc123!@"); err != nil {
		t.Fatalf("password válida con todos los requisitos fue rechazada: %v", err)
	}

	// Test bcrypt length limit
	over := make([]byte, 73)
	for i := range over {
		over[i] = 'a'
	}
	if err := ValidateMinimumPasswordPolicy(string(over)); err == nil {
		t.Fatal("password de más de 72 caracteres debería fallar")
	}
}

func TestValidatePasswordPolicy_LengthAndComplexity(t *testing.T) {
	rule := []byte(`{"min_length":8,"require_uppercase":true,"require_numbers":true,"require_symbols":true}`)
	if err := ValidatePasswordPolicy(rule, "Abc1!def"); err != nil {
		t.Fatalf("password válida fue rechazada: %v", err)
	}
	if err := ValidatePasswordPolicy(rule, "abc"); err == nil {
		t.Fatal("password corta debería fallar")
	}
	over := make([]byte, 100)
	for i := range over {
		over[i] = 'A'
	}
	if err := ValidatePasswordPolicy(rule, string(over)); err == nil {
		t.Fatal("password que excede el límite de bcrypt debería fallar")
	}
}

func TestRegistrationPolicy_RejectsNonPublic(t *testing.T) {
	if _, err := ValidateRegistrationPolicy([]byte(`{"mode":"admin_only","default_role":"USER"}`)); err == nil {
		t.Fatal("modo no público debería rechazar el auto-registro")
	}
	if _, err := ValidateRegistrationPolicy([]byte(`{"mode":"public","default_role":"USER"}`)); err != nil {
		t.Fatalf("modo público debería permitirse: %v", err)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("APP_BASE_URL", "https://auth.example.com/")
	if !IsProduction() {
		t.Fatal("ENV=production debería ser producción")
	}
	if got := BaseURL(); got != "https://auth.example.com" {
		t.Fatalf("BaseURL incorrecto: %q", got)
	}

	// Forzar https aunque APP_BASE_URL tenga http:// en producción
	t.Setenv("APP_BASE_URL", "http://auth.example.com")
	if got := BaseURL(); got != "https://auth.example.com" {
		t.Fatalf("BaseURL debería forzar https en producción, obtuvo: %q", got)
	}

	// En desarrollo respeta http
	t.Setenv("ENV", "development")
	if got := BaseURL(); got != "http://auth.example.com" {
		t.Fatalf("BaseURL debería mantener http en desarrollo, obtuvo: %q", got)
	}

	if !SameOriginRequest("https://auth.example.com/x", "auth.example.com") {
		t.Fatal("mismo host debería ser same-origin")
	}
	if SameOriginRequest("https://evil.com", "auth.example.com") {
		t.Fatal("host distinto no debería ser same-origin")
	}
}

func TestValidateSessionPolicy_BoundsAndFormats(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
		wantMinutes int
	}{
		{
			name:        "duración válida mínima (5 min)",
			input:       `{"token_expiration_minutes": 5}`,
			wantErr:     false,
			wantMinutes: 5,
		},
		{
			name:        "duración válida común (15 min)",
			input:       `{"token_expiration_minutes": 15}`,
			wantErr:     false,
			wantMinutes: 15,
		},
		{
			name:        "duración válida máxima (10080 min / 7 días)",
			input:       `{"token_expiration_minutes": 10080}`,
			wantErr:     false,
			wantMinutes: 10080,
		},
		{
			name:        "duración menor al mínimo (4 min)",
			input:       `{"token_expiration_minutes": 4}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración cero",
			input:       `{"token_expiration_minutes": 0}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración negativa",
			input:       `{"token_expiration_minutes": -10}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración excede el máximo (10081 min)",
			input:       `{"token_expiration_minutes": 10081}`,
			wantErr:     true,
			errContains: "excede el máximo permitido",
		},
		{
			name:        "JSON malformado",
			input:       `{token_expiration_minutes: 60`,
			wantErr:     true,
			errContains: "invalid SESSION_POLICY rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := ValidateSessionPolicy([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("se esperaba error pero fue nil")
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("se esperaba error conteniendo %q, obtenido: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("no se esperaba error, obtenido: %v", err)
				}
				if sess.TokenExpirationMinutes != tc.wantMinutes {
					t.Fatalf("TokenExpirationMinutes = %d, esperado: %d", sess.TokenExpirationMinutes, tc.wantMinutes)
				}
			}
		})
	}
}
