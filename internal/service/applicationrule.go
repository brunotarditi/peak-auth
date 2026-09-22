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
	policyFound := false
	for _, rule := range rules {
		switch rule.Code {
		case util.PWD_POLICY:
			policyFound = true
			if err := util.ValidatePasswordPolicy(rule.Value, req.Password); err != nil {
				return nil, err
			}
		case util.REGISTRATION_POLICY:
			regRule, err := util.ValidateRegistrationPolicy(rule.Value)
			if err != nil {
				return nil, err
			}
			policy = regRule
		}
	}

	// Enforce minimum password policy when no active PWD_POLICY exists
	// This prevents weak passwords when rules are deleted, deactivated, or misconfigured
	if !policyFound {
		if err := util.ValidateMinimumPasswordPolicy(req.Password); err != nil {
			return nil, err
		}
	}

	// Validación crítica de seguridad:
	if policy == nil || policy.DefaultRole == "" {
		return nil, fmt.Errorf("configuración incompleta: la aplicación no tiene un rol por defecto configurado en %s", util.REGISTRATION_POLICY)
	}

	// Defensa en profundidad: el auto-registro nunca puede otorgar ROOT ni ADMIN.
	if strings.EqualFold(policy.DefaultRole, "ROOT") || strings.EqualFold(policy.DefaultRole, "ADMIN") {
		return nil, fmt.Errorf("el registro público no puede asignar roles administrativos (ROOT o ADMIN)")
	}

	return policy, nil
}

// ValidateLogin aplica reglas que afectan el proceso de login. Actualmente
// evalúa si el usuario tiene acceso a la aplicación.
func (s *applicationRuleService) ValidateLogin(appID uint, userID uint) error {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		// Sanitize repository/database errors - do not expose internal details
		return fmt.Errorf("no se pudo obtener las reglas de la aplicación")
	}

	// 1. Verificar que el usuario pertenezca a la aplicación.
	roles, err := s.uarRepo.FindRolesByUserAndApp(userID, appID)
	if err != nil || len(roles) == 0 {
		return fmt.Errorf("el usuario no tiene acceso a esta aplicación")
	}

	for _, rule := range rules {
		switch rule.Code {
		case util.AUTHZ_POLICY:
			if _, err := util.ParseAuthzPolicy(rule.Value); err != nil {
				// Sanitize parser errors - do not expose internal details
				return fmt.Errorf("no se pudo interpretar la política de autorización")
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
	if code == util.REGISTRATION_POLICY {
		if policy, err := util.ParseRegistrationPolicy(value); err == nil {
			if strings.EqualFold(policy.DefaultRole, "ROOT") {
				return fmt.Errorf("el rol por defecto no puede ser ROOT")
			}
			if policy.Mode == "public" && strings.EqualFold(policy.DefaultRole, "ADMIN") {
				return fmt.Errorf("el registro público no puede tener como rol por defecto ADMIN")
			}
		}
	}
	if code == util.SESSION_POLICY {
		if _, err := util.ValidateSessionPolicy(value); err != nil {
			return fmt.Errorf("política de sesión inválida: %w", err)
		}
	}
	return s.ruleRepo.CreateRule(appID, code, value)
}

func (s *applicationRuleService) UpdateRuleValue(appID uint, code string, value []byte) error {
	// Defensa transversal: jamás permitir que el rol por defecto del auto-registro
	// sea ROOT o ADMIN en modo público.
	if code == util.REGISTRATION_POLICY {
		if policy, err := util.ParseRegistrationPolicy(value); err == nil {
			if strings.EqualFold(policy.DefaultRole, "ROOT") {
				return fmt.Errorf("el rol por defecto no puede ser ROOT")
			}
			if policy.Mode == "public" && strings.EqualFold(policy.DefaultRole, "ADMIN") {
				return fmt.Errorf("el registro público no puede tener como rol por defecto ADMIN")
			}
		}
	}

	if code == util.SESSION_POLICY {
		if _, err := util.ValidateSessionPolicy(value); err != nil {
			return fmt.Errorf("política de sesión inválida: %w", err)
		}
	}

	// Protecciones para la App Raíz (resuelta por AppID, no por ID fijo)
	if s.isRootApp(appID) {
		if code == util.AUTHZ_POLICY {
			policy, _ := util.ParseAuthzPolicy(value)
			if !policy.EnableRoles {
				return fmt.Errorf("la autorización por roles es obligatoria para la aplicación raíz")
			}
		}
		if code == util.REGISTRATION_POLICY {
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
