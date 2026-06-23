package util

import "testing"

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
	if !SameOriginRequest("https://auth.example.com/x", "auth.example.com") {
		t.Fatal("mismo host debería ser same-origin")
	}
	if SameOriginRequest("https://evil.com", "auth.example.com") {
		t.Fatal("host distinto no debería ser same-origin")
	}
}
