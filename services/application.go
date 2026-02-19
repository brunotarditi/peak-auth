package services

import (
	"peak-auth/models"
	"peak-auth/repositories"
	"peak-auth/responses"
	"peak-auth/utils"
)

type ApplicationService interface {
	CreateApp(name, description string, isActive bool) (models.Application, error)
	RegisterUserInApp(userEmail, appID, roleName string) error
	GetAppDetails(appID string) (models.Application, error)
	GetDashboardStats() ([]responses.AppStatsResponse, error)
}

type applicationService struct {
	repo     repositories.ApplicationRepository
	userRepo repositories.UserRepository
	roleRepo repositories.RoleRepository
	uarRepo  repositories.UserApplicationRoleRepository
}

func NewApplicationService(repo repositories.ApplicationRepository, userRepo repositories.UserRepository, roleRepo repositories.RoleRepository, uarRepo repositories.UserApplicationRoleRepository) ApplicationService {
	return &applicationService{repo: repo, userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo}
}

/*
Función para crear la app en PEAK AUTH
parámetros: nombre de la app, descripción y si está activo
*/
func (s *applicationService) CreateApp(name, description string, isActive bool) (models.Application, error) {
	// 1. Generamos el Secret Key
	plainSecret, _, err := utils.GenerateToken(32)
	if err != nil {
		return models.Application{}, err
	}

	// 2. Hasheamos el secreto
	hashedSecret, err := utils.HashPassword(plainSecret)
	if err != nil {
		return models.Application{}, err
	}

	// 3. Generamos el AppID amigable (Slug)
	// Esto es lo que la Librería pondrá en su .env como PEAK_APP_ID
	slugID := utils.Slugify(name)

	app := models.Application{
		AppID:       slugID,
		Name:        name,
		Description: description,
		SecretKey:   hashedSecret,
		IsActive:    isActive,
	}

	err = s.repo.Create(&app)
	if err != nil {
		return models.Application{}, err
	}
	// IMPORTANTE: Devolvemos el 'plainSecret' solo esta vez para que el Admin lo vea.
	// Una vez que cerramos esta respuesta, el secreto plano se pierde para siempre.
	app.SecretKey = plainSecret
	return app, nil
}

/*
Función para registrar al usuario en la app creada
parámetros: email del usuario, app ID y el nombre del rol
*/
func (s *applicationService) RegisterUserInApp(userEmail, publicAppID, roleName string) error {
	app, err := s.repo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}

	user, err := s.userRepo.FindByEmail(userEmail)
	if err != nil {
		return err
	}

	role, err := s.roleRepo.FindByRoleName(roleName)
	if err != nil {
		return err
	}

	return s.uarRepo.AssignRole(user.ID, app.ID, role.ID)
}

func (s *applicationService) GetAppDetails(publicAppID string) (models.Application, error) {
	return s.repo.FindByAppID(publicAppID)
}

func (s *applicationService) GetDashboardStats() ([]responses.AppStatsResponse, error) {
	return s.repo.GetAppsWithUserCount()
}
