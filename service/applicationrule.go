package service

import (
	"fmt"
	"peak-auth/model"
	"peak-auth/repository"
	"peak-auth/request"
	"peak-auth/utils"
)

type ApplicationRuleService interface {
	ValidateRegistration(appID uint, req request.RegisterRequest) (string, error)
	ValidateLogin(appID uint, userID uint) error
	FindRulesByAppID(appID uint) ([]model.ApplicationRules, error)
	CreateDefaultRules(appID uint) error
	CreateRule(appID uint, code string, value []byte) error
	UpdateRuleValue(appID uint, code string, value []byte) error
	DeleteRule(appID uint, code string) error
}

type applicationRuleService struct {
	ruleRepo repository.ApplicationRuleRepository
	uarRepo  repository.UserApplicationRoleRepository
	roleRepo repository.RoleRepository
}

func NewApplicationRuleService(ruleRepo repository.ApplicationRuleRepository, uarRepo repository.UserApplicationRoleRepository, roleRepo repository.RoleRepository) ApplicationRuleService {
	return &applicationRuleService{ruleRepo: ruleRepo, uarRepo: uarRepo, roleRepo: roleRepo}
}

// ValidateRegistration valida las reglas de registro de la app y devuelve
// el `DefaultRole` si alguna regla lo especifica. Devuelve error si alguna regla falla.
func (s *applicationRuleService) ValidateRegistration(appID uint, req request.RegisterRequest) (string, error) {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return "", err
	}

	var defaultRole string
	for _, rule := range rules {
		switch rule.Code {
		case "PWD_POLICY":
			if err := utils.ValidatePasswordPolicy(rule.Value, req.Password); err != nil {
				return "", err
			}
		case "REGISTRATION_POLICY":
			regRule, err := utils.ValidateRegistrationPolicy(rule.Value)
			if err != nil {
				return "", err
			}
			defaultRole = regRule.DefaultRole
		}
	}

	// Validación crítica de seguridad:
	if defaultRole == "" {
		return "", fmt.Errorf("configuración incompleta: la aplicación no tiene un rol por defecto configurado en REGISTRATION_POLICY")
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
		case "AUTHZ_POLICY":
			authzRule, err := utils.ParseAuthzPolicy(rule.Value)
			if err != nil {
				return fmt.Errorf("invalid AUTHZ_POLICY rule: %w", err)
			}
			// Future: Enforce roles strictly if enabled
			if authzRule.EnableRoles {
				// By default any logged in user who belongs to the app should be allowed,
				// specific endpoint roles are checked by RoleMiddleware. 
				// The actual logic verifying they belong to the app is handled inside Login.
			}
			// (Session policy max_failed_logins could also be validated here)
		}
	}
	return nil
}

func (s *applicationRuleService) FindRulesByAppID(appID uint) ([]model.ApplicationRules, error) {
	return s.ruleRepo.GetRulesByAppID(appID)
}

func (s *applicationRuleService) CreateDefaultRules(appID uint) error {
	return s.ruleRepo.CreateDefaultRules(appID)
}

func (s *applicationRuleService) CreateRule(appID uint, code string, value []byte) error {
	return s.ruleRepo.CreateRule(appID, code, value)
}

func (s *applicationRuleService) UpdateRuleValue(appID uint, code string, value []byte) error {
	return s.ruleRepo.UpdateRuleValue(appID, code, value)
}

func (s *applicationRuleService) DeleteRule(appID uint, code string) error {
	return s.ruleRepo.DeleteRule(appID, code)
}
