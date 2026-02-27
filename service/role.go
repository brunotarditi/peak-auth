package service

import (
	"errors"
	"peak-auth/model"
	"peak-auth/repository"
	"strings"
)

type RoleService interface {
	FindAll() ([]model.Role, error)
	CreateRole(name string) error
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
