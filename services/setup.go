package services

import (
	"errors"
	"peak-auth/models"
	"peak-auth/repositories"
	"peak-auth/utils"
)

type SetupService interface {
	CreateRootUser(email, password, token string) error
	ValidateSetupToken(token string) bool
	IsFirstRun() (bool, error)
}

type setupService struct {
	userRepo   repositories.UserRepository
	appRepo    repositories.ApplicationRepository
	roleRepo   repositories.RoleRepository
	uarRepo    repositories.UserApplicationRoleRepository
	setupRepo  repositories.SetupRepository
	setupToken string
}

func NewSetupService(userRepo repositories.UserRepository, appRepo repositories.ApplicationRepository, roleRepo repositories.RoleRepository, uarRepo repositories.UserApplicationRoleRepository, setupRepo repositories.SetupRepository, setupToken string) SetupService {
	return &setupService{userRepo: userRepo, appRepo: appRepo, roleRepo: roleRepo, uarRepo: uarRepo, setupRepo: setupRepo, setupToken: setupToken}
}

func (s *setupService) CreateRootUser(email, password, token string) error {

	if !s.ValidateSetupToken(token) {
		return errors.New("token de setup inválido")
	}

	hashedPassword, _ := utils.HashPassword(password)

	name := "Peak Auth Raíz"
	appId := utils.Slugify(name)
	// Definimos la estructura inicial
	rootApp := models.Application{Name: name, AppID: appId, IsActive: true}
	rootRole := models.Role{Name: "ROOT"}
	user := models.User{Email: email, Password: hashedPassword, IsVerified: true}
	profile := models.Profile{FirstName: "System", LastName: "Root"}

	// Ejecutamos las operaciones usando los repositorios disponibles.
	// Intentamos crear la aplicación
	if err := s.appRepo.Create(&rootApp); err != nil {
		return err
	}

	// Creamos el rol raíz
	if err := s.roleRepo.Create(&rootRole); err != nil {
		return err
	}

	// Creamos el usuario con perfil
	if err := s.userRepo.CreateWithProfile(&user, &profile); err != nil {
		return err
	}

	// Asignamos el rol ROOT al usuario dentro de la app creada
	if err := s.uarRepo.AssignRole(user.ID, rootApp.ID, rootRole.ID); err != nil {
		return err
	}

	return nil
}

func (s *setupService) ValidateSetupToken(token string) bool {
	// Simple validation: comparar con el token configurado en el servicio
	return token == s.setupToken
}

func (s *setupService) IsFirstRun() (bool, error) {
	return s.setupRepo.IsFirstRun()
}
