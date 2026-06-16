package service

import (
	"fmt"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"time"
)

type ApplicationService interface {
	CreateApp(name, description string, isActive bool) (model.Application, string, error)
	UpdateApp(appID string, description string, isActive bool) error
	ValidateAppNameUnique(name string) error
	RegenerateSecret(appID string) (string, error)
	RegisterUserInApp(userEmail, roleName string, app *model.Application) error
	RevokeUserFromApp(userID, appID uint) error
	GetAppDetails(appID string) (model.Application, error)
	DeleteApp(appID string) error
	GetDashboardStats() ([]response.AppStatsResponse, error)
	GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error)
}

type applicationService struct {
	repo         repo.ApplicationRepository
	userRepo     repo.UserRepository
	roleRepo     repo.RoleRepository
	uarRepo      repo.UserApplicationRoleRepository
	txManager    repo.TransactionManager
	emailService *EmailService
	passRepo     repo.PasswordResetRepository
}

func NewApplicationService(repo repo.ApplicationRepository, userRepo repo.UserRepository, roleRepo repo.RoleRepository, uarRepo repo.UserApplicationRoleRepository, txManager repo.TransactionManager, emailService *EmailService, passRepo repo.PasswordResetRepository) ApplicationService {
	return &applicationService{repo: repo, userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, txManager: txManager, emailService: emailService, passRepo: passRepo}
}

func (s *applicationService) CreateApp(name, description string, isActive bool) (model.Application, string, error) {
	plainSecret, _, err := util.GenerateToken(32)
	if err != nil {
		return model.Application{}, "", err
	}

	hashedSecret, err := util.HashPassword(plainSecret)
	if err != nil {
		return model.Application{}, "", err
	}

	slugID := util.Slugify(name)

	// Verificar colisión de slug y añadir sufijo si es necesario
	baseSlug := slugID
	attempt := 1
	for {
		_, err := s.repo.FindByAppID(slugID)
		if err != nil {
			break // Slug disponible
		}
		slugID = fmt.Sprintf("%s-%d", baseSlug, attempt)
		attempt++
	}

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

func (s *applicationService) RegisterUserInApp(userEmail, roleName string, app *model.Application) error {

	role, err := s.roleRepo.FindByRoleName(roleName)
	if err != nil {
		return err
	}

	return s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		user, err := tx.Users().FindByEmail(userEmail)
		isNewUser := false

		if err != nil {
			// ESCENARIO 1: Usuario NO existe globalmente. Lo creamos.
			isNewUser = true

			// Generamos un password aleatorio temporal.
			// Útil para que la fila en DB sea válida y la cuenta esté 'cerrada'
			// hasta que el usuario use el link de activación (reset password).
			placeholderPass, _, _ := util.GenerateToken(16)
			hashedPass, _ := util.HashPassword(placeholderPass)

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

		// ACTIVACIÓN: Enviamos email de verificación estándar.
		if isNewUser || !user.IsVerified {
			plainToken, hashedToken, _ := util.GenerateToken(32)
			verification := model.EmailVerification{
				UserID:        user.ID,
				ApplicationID: app.ID,
				TokenHash:     hashedToken,
				ExpiresAt:     time.Now().Add(24 * time.Hour),
			}
			if err := tx.EmailVerifications().CreateEmailVerification(&verification); err != nil {
				return err
			}
			// Envío asíncrono
			go s.emailService.SendVerificationEmail(user.Email, plainToken, app.Name)
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
	if appID == util.AppIdPeakAuth {
		isActive = true
	}

	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return err
	}

	app.Description = description
	app.IsActive = isActive

	return s.repo.Update(&app)
}

func (s *applicationService) RegenerateSecret(appID string) (string, error) {
	if appID == util.AppIdPeakAuth {
		return "", fmt.Errorf("la aplicación raíz no requiere ni permite la regeneración de Client Secret")
	}
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return "", err
	}

	plainSecret, _, err := util.GenerateToken(32)
	if err != nil {
		return "", err
	}

	hashedSecret, err := util.HashPassword(plainSecret)
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
	if appID == util.AppIdPeakAuth {
		return fmt.Errorf("la aplicación raíz es vital para el sistema y no puede ser eliminada")
	}
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return err
	}

	users, err := s.uarRepo.GetUsersWithRolesByApp(app.ID)
	if err == nil && len(users) > 0 {
		return fmt.Errorf("no se puede eliminar la aplicación porque tiene usuarios vinculados. Revoca el acceso a todos los usuarios primero.")
	}

	return s.repo.Delete(app.ID)
}

func (s *applicationService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsWithUserCount()
}

func (s *applicationService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsForUser(userID)
}
