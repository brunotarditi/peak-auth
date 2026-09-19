package util

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type RegistrationPolicy struct {
	Mode                     string `json:"mode"`
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

type MfaPolicy struct {
	Mode string `json:"mode"` // "OPTIONAL", "REQUIRED", "DISABLED"
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

// ValidatePasswordLength garantiza que la contraseña no exceda el límite de bcrypt.
func ValidatePasswordLength(password string) error {
	if len(password) > BcryptMaxPasswordBytes {
		return fmt.Errorf("la contraseña no puede superar los %d caracteres", BcryptMaxPasswordBytes)
	}
	return nil
}

// ValidatePasswordPolicy checks if a plaintext password satisfies the configured constraints.
func ValidatePasswordPolicy(raw []byte, password string) error {
	var r PasswordPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid PWD_POLICY rule: %w", err)
	}

	if err := ValidatePasswordLength(password); err != nil {
		return err
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

// ParseMfaPolicy extracts MFA constraints
func ParseMfaPolicy(raw []byte) (*MfaPolicy, error) {
	var r MfaPolicy
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid MFA_POLICY rule: %w", err)
	}
	return &r, nil
}

// ValidatePasswordStrength checks a password against hardcoded best practices (for root/setup)
func ValidatePasswordStrength(password string) bool {
	if len(password) < 8 || len(password) > BcryptMaxPasswordBytes {
		return false
	}
	hasUpper, _ := regexp.MatchString("[A-Z]", password)
	hasLower, _ := regexp.MatchString("[a-z]", password)
	hasNumber, _ := regexp.MatchString("[0-9]", password)
	hasSymbol, _ := regexp.MatchString("[^A-Za-z0-9]", password)
	return hasUpper && hasLower && hasNumber && hasSymbol
}

// ValidateMinimumPasswordPolicy enforces a baseline password policy when no active PWD_POLICY exists.
// This prevents weak passwords from being set during password reset or other operations when
// application rules are missing, deactivated, or misconfigured.
// This enforces the same baseline complexity as the default PWD_POLICY to ensure consistent
// security requirements across all password-setting paths.
func ValidateMinimumPasswordPolicy(password string) error {
	if err := ValidatePasswordLength(password); err != nil {
		return err
	}

	// Enforce the same baseline requirements as the default PWD_POLICY:
	// min_length: 8, require_uppercase: true, require_numbers: true, require_symbols: true
	if len(password) < 8 {
		return fmt.Errorf("la contraseña debe tener al menos 8 caracteres")
	}

	matched, _ := regexp.MatchString("[A-Z]", password)
	if !matched {
		return fmt.Errorf("la contraseña debe contener al menos una letra mayúscula")
	}

	matched, _ = regexp.MatchString("[0-9]", password)
	if !matched {
		return fmt.Errorf("la contraseña debe contener al menos un dígito")
	}

	matched, _ = regexp.MatchString("[^A-Za-z0-9]", password)
	if !matched {
		return fmt.Errorf("la contraseña debe contener al menos un símbolo")
	}

	return nil
}


