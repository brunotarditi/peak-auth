package utils

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type RegistrationPolicy struct {
	Mode                     string `json:"mode"` // Can be: "public", "admin_only"
	RequireEmailVerification bool   `json:"require_email_verification"`
	DefaultRole              string `json:"default_role"`
}

type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
}

type SessionPolicy struct {
	TokenExpirationMinutes int `json:"token_expiration_minutes"`
	MaxFailedLogins        int `json:"max_failed_logins"`
}

type AuthzPolicy struct {
	EnableRoles bool `json:"enable_roles"`
}

// ValidateRegistrationPolicy parses the policy and validates whether self register is allowed.
// Returns the parsed policy to allow retrieving the DefaultRole or Verification rule.
func ValidateRegistrationPolicy(raw []byte) (*RegistrationPolicy, error) {
	var r RegistrationPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid REGISTRATION_POLICY rule: %w", err)
	}
	if r.Mode != "public" {
		return nil, fmt.Errorf("el registro público está deshabilitado para esta aplicación")
	}
	return &r, nil
}

// ParseRegistrationPolicy simply returns the policy struct without enforcing logic (used merely for reading).
func ParseRegistrationPolicy(raw []byte) (*RegistrationPolicy, error) {
	var r RegistrationPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid REGISTRATION_POLICY rule: %w", err)
	}
	return &r, nil
}

// ValidatePasswordPolicy checks if a plaintext password satisfies the configured constraints.
func ValidatePasswordPolicy(raw []byte, password string) error {
	var r PasswordPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid PWD_POLICY rule: %w", err)
	}
	
	if r.MinLength > 0 && len(password) < r.MinLength {
		return fmt.Errorf("la contraseña debe tener al menos %d caracteres", r.MinLength)
	}
	if r.RequireUppercase {
		matched, _ := regexp.MatchString("[A-Z]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos una letra mayúscula")
		}
	}
	if r.RequireNumbers {
		matched, _ := regexp.MatchString("[0-9]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos un dígito")
		}
	}
	if r.RequireSymbols {
		matched, _ := regexp.MatchString("[^A-Za-z0-9]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos un símbolo")
		}
	}
	return nil
}

// ParseSessionPolicy extracts session configuration rules such as token expiration
func ParseSessionPolicy(raw []byte) (*SessionPolicy, error) {
	var r SessionPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid SESSION_POLICY rule: %w", err)
	}
	return &r, nil
}

// ParseAuthzPolicy extracts authorization constraints
func ParseAuthzPolicy(raw []byte) (*AuthzPolicy, error) {
	var r AuthzPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid AUTHZ_POLICY rule: %w", err)
	}
	return &r, nil
}

// ValidatePasswordStrength checks a password against hardcoded best practices (for root/setup)
func ValidatePasswordStrength(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasUpper, _ := regexp.MatchString("[A-Z]", password)
	hasLower, _ := regexp.MatchString("[a-z]", password)
	hasNumber, _ := regexp.MatchString("[0-9]", password)
	hasSymbol, _ := regexp.MatchString("[^A-Za-z0-9]", password)
	return hasUpper && hasLower && hasNumber && hasSymbol
}
