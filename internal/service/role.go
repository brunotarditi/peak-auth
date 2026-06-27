package service

import (
	"errors"
	"fmt"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strings"
)

// reservedRoleNames son nombres que pertenecen al sistema de plataforma y no
// pueden ser creados/duplicados como roles propios de una aplicación.
var reservedRoleNames = map[string]bool{
	"ROOT":  true,
	"ADMIN": true,
	"USER":  true,
}

type RoleService interface {
	FindAll() ([]model.Role, error)
	FindVisibleForApp(appID uint) ([]model.Role, error)
	CreateRole(name string) error
	CreateAppRole(name string, appID uint) error
	DeleteRole(name string) error
	DeleteAppRole(name string, appID uint) error
}

type roleService struct {
	repo     repo.RoleRepository
	ruleRepo repo.ApplicationRuleRepository
}

func NewRoleService(repo repo.RoleRepository, ruleRepo repo.ApplicationRuleRepository) RoleService {
	return &roleService{repo: repo, ruleRepo: ruleRepo}
}

func (s *roleService) FindAll() ([]model.Role, error) {
	return s.repo.FindAll()
}

// FindVisibleForApp devuelve los roles globales del sistema + los propios de la app.
func (s *roleService) FindVisibleForApp(appID uint) ([]model.Role, error) {
	return s.repo.FindVisibleForApp(appID)
}

// CreateRole crea un rol GLOBAL del sistema (reservado a la plataforma).
func (s *roleService) CreateRole(name string) error {
	roleName := strings.ToUpper(strings.TrimSpace(name))
	if roleName == "" {
		return errors.New("el nombre del rol es obligatorio")
	}

	_, err := s.repo.FindGlobalByName(roleName)
	if err == nil {
		return errors.New("el rol ya existe")
	}

	role := model.Role{Name: roleName, ApplicationID: nil}
	return s.repo.Create(&role)
}

// CreateAppRole crea un rol PROPIO de una aplicación. Requiere que la app tenga
// el sistema de roles habilitado (AUTHZ_POLICY.enable_roles = true) y no permite
// re-declarar roles reservados del sistema (ROOT/ADMIN/USER ya son globales).
func (s *roleService) CreateAppRole(name string, appID uint) error {
	roleName := strings.ToUpper(strings.TrimSpace(name))
	if roleName == "" {
		return errors.New("el nombre del rol es obligatorio")
	}
	if reservedRoleNames[roleName] {
		return fmt.Errorf("el rol \"%s\" es un rol del sistema y no puede crearse como rol de aplicación", roleName)
	}

	if !s.appHasRolesEnabled(appID) {
		return errors.New("esta aplicación no tiene el sistema de roles habilitado")
	}

	// Evitar duplicados dentro de la misma app.
	if _, err := s.repo.FindByNameForApp(roleName, appID); err == nil {
		return errors.New("el rol ya existe en esta aplicación")
	}

	appIDCopy := appID
	role := model.Role{Name: roleName, ApplicationID: &appIDCopy}
	return s.repo.Create(&role)
}

func (s *roleService) DeleteRole(name string) error {
	roleName := strings.ToUpper(strings.TrimSpace(name))

	role, err := s.repo.FindGlobalByName(roleName)
	if err != nil {
		return errors.New("el rol no existe")
	}

	if role.IsDefault {
		return fmt.Errorf("el rol \"%s\" es un rol protegido del sistema y no puede eliminarse", roleName)
	}

	count, err := s.repo.CountUsersWithRole(role.ID)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("no se puede eliminar: %d usuario(s) tienen asignado el rol \"%s\"", count, roleName)
	}

	return s.repo.Delete(role.ID)
}

// DeleteAppRole elimina un rol propio de la aplicación indicada.
func (s *roleService) DeleteAppRole(name string, appID uint) error {
	roleName := strings.ToUpper(strings.TrimSpace(name))

	role, err := s.repo.FindByNameForApp(roleName, appID)
	if err != nil {
		return errors.New("el rol no existe en esta aplicación")
	}

	// Solo se pueden borrar roles que efectivamente pertenezcan a la app
	// (no los globales del sistema, aunque se vean desde la app).
	if role.ApplicationID == nil || *role.ApplicationID != appID {
		return errors.New("solo pueden eliminarse los roles propios de la aplicación")
	}

	count, err := s.repo.CountUsersWithRole(role.ID)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("no se puede eliminar: %d usuario(s) tienen asignado el rol \"%s\"", count, roleName)
	}

	return s.repo.Delete(role.ID)
}

func (s *roleService) appHasRolesEnabled(appID uint) bool {
	rules, err := s.ruleRepo.GetRulesByAppID(appID)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if r.Code == "AUTHZ_POLICY" {
			policy, err := util.ParseAuthzPolicy(r.Value)
			if err != nil {
				return false
			}
			return policy.EnableRoles
		}
	}
	return false
}
