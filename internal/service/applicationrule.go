package service

import (
	"fmt"
	"peak-auth/internal/api/dto"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

type ApplicationRuleService interface {
	ValidateRegistration(appID uint, req dto.RegisterRequest) (*util.RegistrationPolicy, error)
	ValidateLogin(appID uint, userID uint) error
	FindRulesByAppID(appID uint) ([]model.ApplicationRules, error)
	CreateDefaultRules(appID uint) error
	CreateRule(appID uint, code string, value []byte) error
	UpdateRuleValue(appID uint, code string, value []byte) error
	DeleteRule(appID uint, code string) error
}

type applicationRuleService struct {
	ruleRepo repo.ApplicationRuleRepository
	uarRepo  repo.UserApplicationRoleRepository
	roleRepo repo.RoleRepository
}

func NewApplicationRuleService(ruleRepo repo.ApplicationRuleRepository, uarRepo repo.UserApplicationRoleRepository, roleRepo repo.RoleRepository) ApplicationRuleService {
	return &applicationRuleService{ruleRepo: ruleRepo, uarRepo: uarRepo, roleRepo: roleRepo}
}

// ValidateRegistration valida las reglas de registro de la app y devuelve
// la política completa (incluyendo DefaultRole y RequireEmailVerification) si alguna regla lo especifica.
func (s *applicationRuleService) ValidateRegistration(appID uint, req dto.RegisterRequest) (*util.RegistrationPolicy, error) {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return nil, err
	}

	var policy *util.RegistrationPolicy
	for _, rule := range rules {
		switch rule.Code {
		case "PWD_POLICY":
			if err := util.ValidatePasswordPolicy(rule.Value, req.Password); err != nil {
				return nil, err
			}
		case "REGISTRATION_POLICY":
			regRule, err := util.ValidateRegistrationPolicy(rule.Value)
			if err != nil {
				return nil, err
			}
			policy = regRule
		}
	}

	// Validación crítica de seguridad:
	if policy == nil || policy.DefaultRole == "" {
		return nil, fmt.Errorf("configuración incompleta: la aplicación no tiene un rol por defecto configurado en REGISTRATION_POLICY")
	}

	return policy, nil
}

// ValidateLogin aplica reglas que afectan el proceso de login. Actualmente
// evalúa si el usuario tiene acceso a la aplicación.
func (s *applicationRuleService) ValidateLogin(appID uint, userID uint) error {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return err
	}

	// 1. Verificar que el usuario pertenezca a la aplicación.
	roles, err := s.uarRepo.FindRolesByUserAndApp(userID, appID)
	if err != nil || len(roles) == 0 {
		return fmt.Errorf("el usuario no tiene acceso a esta aplicación")
	}

	for _, rule := range rules {
		switch rule.Code {
		case "AUTHZ_POLICY":
			authzRule, err := util.ParseAuthzPolicy(rule.Value)
			if err != nil {
				return fmt.Errorf("regla AUTHZ_POLICY inválida: %w", err)
			}
			// (Futuro: Verificación de roles específicos requeridos si se habilita)
			if authzRule.EnableRoles {
				// El usuario ya tiene roles (chequeado arriba), se permite el acceso base.
			}
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
	// Protecciones para la App Raíz (ID 1)
	if appID == 1 {
		if code == "AUTHZ_POLICY" {
			policy, _ := util.ParseAuthzPolicy(value)
			if !policy.EnableRoles {
				return fmt.Errorf("la autorización por roles es obligatoria para la aplicación raíz")
			}
		}
		if code == "REGISTRATION_POLICY" {
			policy, _ := util.ParseRegistrationPolicy(value)
			if policy.Mode == "public" {
				return fmt.Errorf("el registro público no está permitido para la aplicación raíz")
			}
			if policy.DefaultRole != "ADMIN" && policy.DefaultRole != "ROOT" {
				return fmt.Errorf("el rol por defecto para la aplicación raíz debe ser ADMIN o ROOT")
			}
		}
	}

	return s.ruleRepo.UpdateRuleValue(appID, code, value)
}

func (s *applicationRuleService) DeleteRule(appID uint, code string) error {
	return s.ruleRepo.DeleteRule(appID, code)
}
