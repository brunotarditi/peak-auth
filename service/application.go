package service

import (
	"peak-auth/model"
	"peak-auth/repository"
	"peak-auth/response"
	"peak-auth/utils"
)

type ApplicationService interface {
	CreateApp(name, description string, isActive bool) (model.Application, string, error)
	RegisterUserInApp(userEmail, appID, roleName string) error
	GetAppDetails(appID string) (model.Application, error)
	GetDashboardStats() ([]response.AppStatsResponse, error)
}

type applicationService struct {
	repo      repository.ApplicationRepository
	userRepo  repository.UserRepository
	roleRepo  repository.RoleRepository
	uarRepo   repository.UserApplicationRoleRepository
	txManager repository.TransactionManager
}

func NewApplicationService(repo repository.ApplicationRepository, userRepo repository.UserRepository, roleRepo repository.RoleRepository, uarRepo repository.UserApplicationRoleRepository, txManager repository.TransactionManager) ApplicationService {
	return &applicationService{repo: repo, userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, txManager: txManager}
}

func (s *applicationService) CreateApp(name, description string, isActive bool) (model.Application, string, error) {
	plainSecret, _, err := utils.GenerateToken(32)
	if err != nil {
		return model.Application{}, "", err
	}

	hashedSecret, err := utils.HashPassword(plainSecret)
	if err != nil {
		return model.Application{}, "", err
	}

	slugID := utils.Slugify(name)

	app := model.Application{
		AppID:       slugID,
		Name:        name,
		Description: description,
		SecretKey:   hashedSecret,
		IsActive:    isActive,
	}

	err = s.repo.Create(&app)
	if err != nil {
		return model.Application{}, "", err
	}

	return app, plainSecret, nil
}

func (s *applicationService) RegisterUserInApp(userEmail, publicAppID, roleName string) error {
	app, err := s.repo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}

	role, err := s.roleRepo.FindByRoleName(roleName)
	if err != nil {
		return err
	}

	return s.txManager.WithinTransaction(func(tx repository.TxRepository) error {
		user, err := tx.Users().FindByEmail(userEmail)

		if err != nil {
			tempPass, _, _ := utils.GenerateToken(16)
			hashedPass, _ := utils.HashPassword(tempPass)

			user = model.User{
				Email:      userEmail,
				Password:   hashedPass,
				IsVerified: false, // Bloqueado hasta que valide mail
			}

			// Perfil inicial genérico
			profile := model.Profile{
				FirstName: "Usuario",
				LastName:  "Invitado",
			}

			if err := tx.Users().CreateWithProfile(&user, &profile); err != nil {
				return err
			}
		}

		// Asignación del rol en la app específica
		return tx.UAR().AssignRole(user.ID, app.ID, role.ID)
	})
}

func (s *applicationService) GetAppDetails(publicAppID string) (model.Application, error) {
	return s.repo.FindByAppID(publicAppID)
}

func (s *applicationService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsWithUserCount()
}
