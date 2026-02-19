package utils

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type SelfRegisterRule struct {
	Allow bool `json:"allow"`
}

type PwdStrengthRule struct {
	Min     int  `json:"min"`
	Upper   bool `json:"upper"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
}

type DefaultRoleRule struct {
	Role string `json:"role"`
}

type AdminOnlyRule struct {
	Enabled bool `json:"enabled"`
}

// ValidateSelfRegister checks SELF_REGISTER rule bytes and returns error if not allowed
func ValidateSelfRegister(raw []byte) error {
	var r SelfRegisterRule
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid SELF_REGISTER rule: %w", err)
	}
	if !r.Allow {
		return fmt.Errorf("registro público deshabilitado por la regla SELF_REGISTER")
	}
	return nil
}

// ValidatePasswordStrength validates password against PwdStrengthRule
func ValidatePasswordStrength(raw []byte, password string) error {
	var r PwdStrengthRule
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid PWD_STRENGTH rule: %w", err)
	}
	if r.Min > 0 && len(password) < r.Min {
		return fmt.Errorf("la contraseña debe tener al menos %d caracteres", r.Min)
	}
	if r.Upper {
		matched, _ := regexp.MatchString("[A-Z]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos una letra mayúscula")
		}
	}
	if r.Digits {
		matched, _ := regexp.MatchString("[0-9]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos un dígito")
		}
	}
	if r.Symbols {
		matched, _ := regexp.MatchString("[^A-Za-z0-9]", password)
		if !matched {
			return fmt.Errorf("la contraseña debe contener al menos un símbolo")
		}
	}
	return nil
}

// ParseDefaultRole extracts role from DEFAULT_ROLE rule
func ParseDefaultRole(raw []byte) (string, error) {
	var r DefaultRoleRule
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("invalid DEFAULT_ROLE rule: %w", err)
	}
	return r.Role, nil
}

// ValidateAdminOnly simply returns error if enabled (actual enforcement should check caller role)
func ValidateAdminOnly(raw []byte) error {
	var r AdminOnlyRule
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("invalid ADMIN_ONLY rule: %w", err)
	}
	if r.Enabled {
		return fmt.Errorf("acción restringida a administradores (ADMIN_ONLY)")
	}
	return nil
}
