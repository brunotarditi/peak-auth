package service

import (
	"fmt"
	"strings"

	"peak-auth/internal/api/request"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

type ApplicationRuleService interface {
	ValidateRegistration(appID uint, req request.RegisterRequest) (*util.RegistrationPolicy, error)
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
	appRepo  repo.ApplicationRepository
}

func NewApplicationRuleService(ruleRepo repo.ApplicationRuleRepository, uarRepo repo.UserApplicationRoleRepository, roleRepo repo.RoleRepository, appRepo repo.ApplicationRepository) ApplicationRuleService {
	return &applicationRuleService{ruleRepo: ruleRepo, uarRepo: uarRepo, roleRepo: roleRepo, appRepo: appRepo}
}

// isRootApp indica si el appID numérico corresponde a la aplicación raíz (peak-auth),
// resolviéndola por su AppID público en lugar de asumir un ID fijo.
func (s *applicationRuleService) isRootApp(appID uint) bool {
	rootApp, err := s.appRepo.FindByAppID(util.AppIdPeakAuth)
	if err != nil {
		return false
	}
	return rootApp.ID == appID
}

// ValidateRegistration valida las reglas de registro de la app y devuelve
// la política completa (incluyendo DefaultRole y RequireEmailVerification) si alguna regla lo especifica.
func (s *applicationRuleService) ValidateRegistration(appID uint, req request.RegisterRequest) (*util.RegistrationPolicy, error) {
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

	// Defensa en profundidad: el auto-registro nunca puede otorgar ROOT.
	if strings.EqualFold(policy.DefaultRole, "ROOT") {
		return nil, fmt.Errorf("el registro automático no puede asignar el rol ROOT")
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
	if code == "REGISTRATION_POLICY" {
		if policy, err := util.ParseRegistrationPolicy(value); err == nil {
			if strings.EqualFold(policy.DefaultRole, "ROOT") {
				return fmt.Errorf("el rol por defecto no puede ser ROOT")
			}
		}
	}
	return s.ruleRepo.CreateRule(appID, code, value)
}

func (s *applicationRuleService) UpdateRuleValue(appID uint, code string, value []byte) error {
	// Defensa transversal: jamás permitir que el rol por defecto del auto-registro
	// sea ROOT (superusuario de plataforma), en ninguna aplicación.
	if code == "REGISTRATION_POLICY" {
		if policy, err := util.ParseRegistrationPolicy(value); err == nil {
			if strings.EqualFold(policy.DefaultRole, "ROOT") {
				return fmt.Errorf("el rol por defecto no puede ser ROOT")
			}
		}
	}

	// Protecciones para la App Raíz (resuelta por AppID, no por ID fijo)
	if s.isRootApp(appID) {
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
