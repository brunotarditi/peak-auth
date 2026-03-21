package service

import (
	"errors"
	"fmt"
	"peak-auth/model"
	"peak-auth/repository"
	"strings"
)

type RoleService interface {
	FindAll() ([]model.Role, error)
	CreateRole(name string) error
	DeleteRole(name string) error
}

type roleService struct {
	repo repository.RoleRepository
}

func NewRoleService(repo repository.RoleRepository) RoleService {
	return &roleService{repo: repo}
}

func (s *roleService) FindAll() ([]model.Role, error) {
	return s.repo.FindAll()
}

func (s *roleService) CreateRole(name string) error {
	roleName := strings.ToUpper(name)

	_, err := s.repo.FindByRoleName(roleName)
	if err == nil {
		return errors.New("el rol ya existe")
	}

	role := model.Role{Name: roleName}
	return s.repo.Create(&role)
}

func (s *roleService) DeleteRole(name string) error {
	roleName := strings.ToUpper(name)

	role, err := s.repo.FindByRoleName(roleName)
	if err != nil {
		return errors.New("el rol no existe")
	}

	// Proteger roles del sistema
	if role.IsDefault {
		return fmt.Errorf("el rol \"%s\" es un rol protegido del sistema y no puede eliminarse", roleName)
	}

	// Verificar que no haya usuarios asignados
	count, err := s.repo.CountUsersWithRole(role.ID)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("no se puede eliminar: %d usuario(s) tienen asignado el rol \"%s\"", count, roleName)
	}

	return s.repo.Delete(role.ID)
}
