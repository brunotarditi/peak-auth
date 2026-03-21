package service

import (
	"fmt"
	"peak-auth/model"
	"peak-auth/repository"
	"peak-auth/response"
	"peak-auth/utils"
	"time"
)

type ApplicationService interface {
	CreateApp(name, description string, isActive bool) (model.Application, string, error)
	UpdateApp(appID string, description string, isActive bool) error
	ValidateAppNameUnique(name string) error
	RegenerateSecret(appID string) (string, error)
	RegisterUserInApp(userEmail, appID, roleName string) error
	RevokeUserFromApp(userID, appID uint) error
	GetAppDetails(appID string) (model.Application, error)
	DeleteApp(appID string) error
	GetDashboardStats() ([]response.AppStatsResponse, error)
	GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error)
}

type applicationService struct {
	repo         repository.ApplicationRepository
	userRepo     repository.UserRepository
	roleRepo     repository.RoleRepository
	uarRepo      repository.UserApplicationRoleRepository
	txManager    repository.TransactionManager
	emailService *EmailService
	passRepo     repository.PasswordResetRepository
}

func NewApplicationService(repo repository.ApplicationRepository, userRepo repository.UserRepository, roleRepo repository.RoleRepository, uarRepo repository.UserApplicationRoleRepository, txManager repository.TransactionManager, emailService *EmailService, passRepo repository.PasswordResetRepository) ApplicationService {
	return &applicationService{repo: repo, userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, txManager: txManager, emailService: emailService, passRepo: passRepo}
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

// ValidateAppNameUnique verifica que no exista otra app activa con ese nombre.
func (s *applicationService) ValidateAppNameUnique(name string) error {
	_, err := s.repo.FindByName(name)
	if err == nil {
		// Si NO hay error, significa que encontró una app con ese nombre
		return fmt.Errorf("ya existe una aplicación con el nombre \"%s\"", name)
	}
	return nil // No existe, podemos continuar
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
		isNewUser := false

		if err != nil {
			// ESCENARIO 1: Usuario NO existe globalmente. Lo creamos.
			isNewUser = true

			// Generamos un password aleatorio temporal.
			// Útil para que la fila en DB sea válida y la cuenta esté 'cerrada'
			// hasta que el usuario use el link de activación (reset password).
			placeholderPass, _, _ := utils.GenerateToken(16)
			hashedPass, _ := utils.HashPassword(placeholderPass)

			user = model.User{
				Email:      userEmail,
				Password:   hashedPass,
				IsVerified: false,
			}

			profile := model.Profile{
				FirstName: "Usuario",
				LastName:  "Invitado",
			}

			if err := tx.Users().CreateWithProfile(&user, &profile); err != nil {
				return err
			}
		}

		// ESCENARIO 2: Usuario ya existe o acaba de ser creado.
		// Vinculamos el rol en la APP actual.
		if err := tx.UAR().AssignRole(user.ID, app.ID, role.ID); err != nil {
			return err
		}

		// ACTIVACIÓN: Si es nuevo o nunca verificó su cuenta, disparamos onboarding.
		if isNewUser || !user.IsVerified {
			plainToken, hashedToken, _ := utils.GenerateToken(32)
			reset := model.PasswordReset{
				UserID:        user.ID,
				ApplicationID: app.ID,
				TokenHash:     hashedToken,
				ExpiresAt:     time.Now().Add(24 * time.Hour),
			}
			if err := tx.PasswordResets().CreatePasswordReset(&reset); err != nil {
				return err
			}
			// Envío asíncrono para no demorar la respuesta del panel
			go s.emailService.SendVerificationEmail(user.Email, plainToken)
		}

		return nil
	})
}

func (s *applicationService) RevokeUserFromApp(userID, appID uint) error {
	return s.uarRepo.RevokeAccess(userID, appID)
}

func (s *applicationService) GetAppDetails(publicAppID string) (model.Application, error) {
	return s.repo.FindByAppID(publicAppID)
}

func (s *applicationService) UpdateApp(appID string, description string, isActive bool) error {
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return err
	}

	app.Description = description
	app.IsActive = isActive

	return s.repo.Update(&app)
}

func (s *applicationService) RegenerateSecret(appID string) (string, error) {
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return "", err
	}

	plainSecret, _, err := utils.GenerateToken(32)
	if err != nil {
		return "", err
	}

	hashedSecret, err := utils.HashPassword(plainSecret)
	if err != nil {
		return "", err
	}

	app.SecretKey = hashedSecret
	err = s.repo.Update(&app)
	if err != nil {
		return "", err
	}

	return plainSecret, nil
}

func (s *applicationService) DeleteApp(appID string) error {
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return err
	}
	return s.repo.Delete(app.ID)
}

func (s *applicationService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsWithUserCount()
}

func (s *applicationService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsForUser(userID)
}
