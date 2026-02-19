package services

import (
	"encoding/json"
	"fmt"
	"peak-auth/models"
	"peak-auth/repositories"
	"peak-auth/requests"
	"peak-auth/utils"
	"strings"
)

type ApplicationRuleService interface {
	ValidateRegistration(appID uint, req requests.RegisterRequest) (string, error)
	ValidateLogin(appID uint, userID uint) error
	FindRulesByAppID(appID uint) ([]models.ApplicationRules, error)
	CreateDefaultRules(appID uint) error
}

type applicationRuleService struct {
	ruleRepo repositories.ApplicationRuleRepository
	uarRepo  repositories.UserApplicationRoleRepository
	roleRepo repositories.RoleRepository
}

func NewApplicationRuleService(ruleRepo repositories.ApplicationRuleRepository, uarRepo repositories.UserApplicationRoleRepository, roleRepo repositories.RoleRepository) ApplicationRuleService {
	return &applicationRuleService{ruleRepo: ruleRepo, uarRepo: uarRepo, roleRepo: roleRepo}
}

// ValidateRegistration valida las reglas de registro de la app y devuelve
// el `DefaultRole` si alguna regla lo especifica. Devuelve error si alguna regla falla.
func (s *applicationRuleService) ValidateRegistration(appID uint, req requests.RegisterRequest) (string, error) {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return "", err
	}

	var defaultRole string
	for _, rule := range rules {
		switch rule.Code {
		case "PWD_STRENGTH":
			if err := utils.ValidatePasswordStrength(rule.Value, req.Password); err != nil {
				return "", err
			}
		case "SELF_REGISTER":
			// Si la regla existe y dice 'false', tiramos error inmediatamente
			if err := utils.ValidateSelfRegister(rule.Value); err != nil {
				return "", fmt.Errorf("el registro público está deshabilitado para esta aplicación")
			}
		case "DEFAULT_ROLE":
			if r, err := utils.ParseDefaultRole(rule.Value); err == nil {
				defaultRole = r
			}
		}
	}

	// Validación crítica de seguridad:
	if defaultRole == "" {
		// Podrías devolver un rol quemado como "USER" o fallar.
		// Fallar es más seguro: obliga al admin a configurar la app en Peak.
		return "", fmt.Errorf("configuración incompleta: la aplicación no tiene un rol por defecto")
	}

	return defaultRole, nil
}

// ValidateLogin aplica reglas que afectan el proceso de login. Actualmente
// evalúa ADMIN_ONLY: si está activado sólo usuarios con rol ADMIN/ROOT en la app pueden logearse.
func (s *applicationRuleService) ValidateLogin(appID uint, userID uint) error {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		switch rule.Code {
		case "ADMIN_ONLY":
			// Parse rule
			var ar utils.AdminOnlyRule
			if err := json.Unmarshal(rule.Value, &ar); err != nil {
				return fmt.Errorf("invalid ADMIN_ONLY rule: %w", err)
			}
			if ar.Enabled {
				// comprobar roles del usuario en la app
				roles, err := s.uarRepo.FindRolesByUserAndApp(userID, appID)
				if err != nil {
					return fmt.Errorf("error comprobando roles: %w", err)
				}
				for _, r := range roles {
					if strings.ToUpper(r.Name) == "ADMIN" || strings.ToUpper(r.Name) == "ROOT" {
						return nil
					}
				}
				return fmt.Errorf("login restringido a administradores")
			}
		}
	}
	return nil
}

func (s *applicationRuleService) FindRulesByAppID(appID uint) ([]models.ApplicationRules, error) {
	return s.ruleRepo.GetRulesByAppID(appID)
}

func (s *applicationRuleService) CreateDefaultRules(appID uint) error {
	return s.ruleRepo.CreateDefaultRules(appID)
}
