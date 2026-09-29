package service

import (
	"fmt"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strings"
	"time"
)

type ApplicationService interface {
	GetAppDetails(appID string) (model.Application, error)
	GetDashboardStats() ([]response.AppStatsResponse, error)
	GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error)
	CreateApp(name, description, redirectURL string, isActive bool, ownerID ...uint) (model.Application, string, error)
	UpdateApp(appID string, description, redirectURL string, isActive bool) error
	DeleteApp(appID string) error
	ValidateAppNameUnique(name string) error
	IsRootUser(userID, appID uint) bool
	UserBelongsToApp(userID, appID uint) (bool, error)
	RegenerateSecret(appID string) (string, error)
	RegisterUserInApp(userEmail, roleName string, app *model.Application, accessTime ...*time.Time) error
	RevokeUserFromApp(userID, appID uint) error
	TransferOwnership(appID string, currentUserID, newOwnerID uint) error
	UpdateUserAccessTime(appID string, targetUserID uint, startsAt, expiresAt *time.Time) error
	GetAppTheme(appID string) (*model.ApplicationTheme, error)
	UpdateAppTheme(appID string, theme *model.ApplicationTheme) error
	ResetAppTheme(appID string) error
}

type applicationService struct {
	repo             repo.ApplicationRepository
	userRepo         repo.UserRepository
	roleRepo         repo.RoleRepository
	uarRepo          repo.UserApplicationRoleRepository
	txManager        repo.TransactionManager
	emailService     *EmailService
	passRepo         repo.PasswordResetRepository
	refreshTokenRepo repo.RefreshTokenRepository
	themeRepo        repo.ApplicationThemeRepository
}

func NewApplicationService(appRepo repo.ApplicationRepository, userRepo repo.UserRepository, roleRepo repo.RoleRepository, uarRepo repo.UserApplicationRoleRepository, txManager repo.TransactionManager, emailService *EmailService, passRepo repo.PasswordResetRepository, refreshTokenRepo repo.RefreshTokenRepository, themeRepo ...repo.ApplicationThemeRepository) ApplicationService {
	var tr repo.ApplicationThemeRepository
	if len(themeRepo) > 0 {
		tr = themeRepo[0]
	}
	return &applicationService{repo: appRepo, userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, txManager: txManager, emailService: emailService, passRepo: passRepo, refreshTokenRepo: refreshTokenRepo, themeRepo: tr}
}

func (s *applicationService) GetAppDetails(publicAppID string) (model.Application, error) {
	return s.repo.FindByAppID(publicAppID)
}

func (s *applicationService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsWithUserCount()
}

func (s *applicationService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return s.repo.GetAppsForUser(userID)
}

func (s *applicationService) CreateApp(name, description, redirectURL string, isActive bool, ownerID ...uint) (model.Application, string, error) {
	if err := ValidateRedirectURISecurity(redirectURL); err != nil {
		return model.Application{}, "", err
	}

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

	var creatorID *uint
	if len(ownerID) > 0 && ownerID[0] > 0 {
		cid := ownerID[0]
		creatorID = &cid
	}

	app := model.Application{
		AppID:       slugID,
		Name:        name,
		Description: description,
		RedirectURL: redirectURL,
		SecretKey:   hashedSecret,
		IsActive:    isActive,
		OwnerID:     creatorID,
	}

	err = s.repo.Create(&app)
	if err != nil {
		return model.Application{}, "", err
	}

	// Si se especificó un creador/propietario, asignarle el rol OWNER y ADMIN dentro de la aplicación
	if creatorID != nil && s.roleRepo != nil && s.uarRepo != nil {
		if ownerRole, err := s.roleRepo.FindGlobalByName("OWNER"); err == nil {
			_ = s.uarRepo.AssignRole(*creatorID, app.ID, ownerRole.ID)
		}
		if adminRole, err := s.roleRepo.FindGlobalByName("ADMIN"); err == nil {
			_ = s.uarRepo.AssignRole(*creatorID, app.ID, adminRole.ID)
		}
	}

	return app, plainSecret, nil
}

func (s *applicationService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	if appID == util.AppIdPeakAuth {
		isActive = true
		redirectURL = ""
	} else {
		if err := ValidateRedirectURISecurity(redirectURL); err != nil {
			return err
		}
	}

	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return err
	}

	wasActive := app.IsActive

	// Usar actualización específica por columnas para evitar condiciones de carrera (Lost Update)
	columns := map[string]interface{}{
		"description":  description,
		"redirect_url": redirectURL,
		"is_active":    isActive,
	}
	if err := s.repo.UpdateColumns(app.ID, columns); err != nil {
		return err
	}

	// Si la aplicación fue desactivada, revocar todos los refresh tokens pendientes
	if wasActive && !isActive && s.refreshTokenRepo != nil {
		_ = s.refreshTokenRepo.DeleteByApp(app.ID)
	}

	return nil
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

// ValidateAppNameUnique verifica que no exista otra app activa con ese nombre.
func (s *applicationService) ValidateAppNameUnique(name string) error {
	_, err := s.repo.FindByName(name)
	if err == nil {
		// Si NO hay error, significa que encontró una app con ese nombre
		return fmt.Errorf("ya existe una aplicación con el nombre \"%s\"", name)
	}
	return nil // No existe, podemos continuar
}

func (s *applicationService) IsRootUser(userID, appID uint) bool {
	roles, err := s.uarRepo.GetUserRolesInApp(userID, appID)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if strings.EqualFold(r, "ROOT") {
			return true
		}
	}
	return false
}

func (s *applicationService) UserBelongsToApp(userID, appID uint) (bool, error) {
	return s.uarRepo.BelongsToApp(userID, appID)
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

	// Usar actualización específica por columnas para no sobrescribir metadata concurrente
	columns := map[string]interface{}{
		"secret_key": hashedSecret,
	}
	err = s.repo.UpdateColumns(app.ID, columns)
	if err != nil {
		return "", err
	}

	return plainSecret, nil
}

func (s *applicationService) RegisterUserInApp(userEmail, roleName string, app *model.Application, accessTime ...*time.Time) error {

	// No se permite asignar el rol de superusuario de plataforma ni rol OWNER directo
	if strings.EqualFold(roleName, "ROOT") {
		return fmt.Errorf("no se puede asignar el rol ROOT")
	}
	if strings.EqualFold(roleName, "OWNER") {
		return fmt.Errorf("no se puede asignar el rol OWNER directamente; utilice la transferencia de propiedad")
	}

	// Resolver el rol con alcance de la app: primero rol propio, luego global.
	role, err := s.roleRepo.FindByNameForApp(roleName, app.ID)
	if err != nil {
		return fmt.Errorf("el rol indicado no existe para esta aplicación")
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
		// Vinculamos el rol en la APP actual con su ventana de acceso temporal.
		if err := tx.UAR().AssignRole(user.ID, app.ID, role.ID, accessTime...); err != nil {
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
	app, err := s.repo.FindByID(appID)
	if err == nil && app.AppID == util.AppIdPeakAuth {
		if s.IsRootUser(userID, appID) {
			return fmt.Errorf("no se puede revocar el acceso al usuario ROOT de la plataforma")
		}
	}
	if err == nil && app.OwnerID != nil && *app.OwnerID == userID {
		return fmt.Errorf("no se puede revocar el acceso al propietario (OWNER) de la aplicación")
	}

	if err := s.uarRepo.RevokeAccess(userID, appID); err != nil {
		return err
	}
	if s.refreshTokenRepo != nil {
		_ = s.refreshTokenRepo.DeleteByUserAndApp(userID, appID)
	}

	// Increment authz_version to immediately invalidate all existing access tokens
	if s.userRepo != nil {
		user, err := s.userRepo.FindById(userID)
		if err == nil {
			_ = s.userRepo.UpdateColumn("authz_version", user.AuthzVersion+1, userID)
		}
	}

	return nil
}

func (s *applicationService) TransferOwnership(appID string, currentUserID, newOwnerID uint) error {
	if appID == util.AppIdPeakAuth {
		return fmt.Errorf("no se puede transferir la propiedad de la aplicación del sistema")
	}

	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return fmt.Errorf("aplicación no encontrada")
	}

	isOwner := app.OwnerID != nil && *app.OwnerID == currentUserID
	if !isOwner {
		return fmt.Errorf("solo el propietario actual puede transferir la propiedad")
	}

	if app.OwnerID != nil && *app.OwnerID == newOwnerID {
		return fmt.Errorf("el usuario ya es el propietario de esta aplicación")
	}

	if s.userRepo != nil {
		newOwner, err := s.userRepo.FindById(newOwnerID)
		if err != nil {
			return fmt.Errorf("el nuevo propietario no fue encontrado")
		}
		if !newOwner.IsActive {
			return fmt.Errorf("el nuevo propietario está desactivado")
		}
		if !newOwner.IsVerified {
			return fmt.Errorf("el nuevo propietario debe estar verificado")
		}
	}

	if s.txManager == nil {
		return s.repo.UpdateColumns(app.ID, map[string]interface{}{"owner_id": newOwnerID})
	}

	return s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		if err := tx.Apps().UpdateColumns(app.ID, map[string]interface{}{"owner_id": newOwnerID}); err != nil {
			return err
		}

		ownerRole, err := tx.Roles().FindGlobalByName("OWNER")
		if err != nil {
			return fmt.Errorf("rol OWNER no configurado en el sistema")
		}
		adminRole, err := tx.Roles().FindGlobalByName("ADMIN")
		if err != nil {
			return fmt.Errorf("rol ADMIN no configurado en el sistema")
		}

		if app.OwnerID != nil {
			oldOwnerID := *app.OwnerID
			_ = tx.UAR().RevokeRole(oldOwnerID, app.ID, ownerRole.ID)
			_ = tx.UAR().AssignRole(oldOwnerID, app.ID, adminRole.ID)

			oldUser, err := tx.Users().FindById(oldOwnerID)
			if err == nil {
				_ = tx.Users().UpdateColumn("authz_version", oldUser.AuthzVersion+1, oldOwnerID)
			}
		}

		_ = tx.UAR().AssignRole(newOwnerID, app.ID, ownerRole.ID)

		newUser, err := tx.Users().FindById(newOwnerID)
		if err == nil {
			_ = tx.Users().UpdateColumn("authz_version", newUser.AuthzVersion+1, newOwnerID)
		}

		return nil
	})
}

func (s *applicationService) UpdateUserAccessTime(appID string, targetUserID uint, startsAt, expiresAt *time.Time) error {
	app, err := s.repo.FindByAppID(appID)
	if err != nil {
		return fmt.Errorf("aplicación no encontrada")
	}

	if err := s.uarRepo.UpdateAccessTime(targetUserID, app.ID, startsAt, expiresAt); err != nil {
		return err
	}

	// Invalida tokens previos del usuario para refrescar claims de acceso
	if s.userRepo != nil {
		user, err := s.userRepo.FindById(targetUserID)
		if err == nil {
			_ = s.userRepo.UpdateColumn("authz_version", user.AuthzVersion+1, targetUserID)
		}
	}

	return nil
}

func (s *applicationService) GetAppTheme(publicAppID string) (*model.ApplicationTheme, error) {
	app, err := s.repo.FindByAppID(publicAppID)
	if err != nil {
		return nil, err
	}
	if s.themeRepo == nil {
		return nil, nil
	}
	return s.themeRepo.FindByAppID(app.ID)
}

func (s *applicationService) UpdateAppTheme(publicAppID string, theme *model.ApplicationTheme) error {
	app, err := s.repo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}
	if theme == nil {
		return fmt.Errorf("tema inválido")
	}
	theme.ApplicationID = app.ID
	if theme.PrimaryColor != "" {
		theme.PrimaryColor = util.SanitizeHexColor(theme.PrimaryColor)
	}
	if s.themeRepo == nil {
		return fmt.Errorf("repositorio de temas no disponible")
	}
	return s.themeRepo.Upsert(theme)
}

func (s *applicationService) ResetAppTheme(publicAppID string) error {
	app, err := s.repo.FindByAppID(publicAppID)
	if err != nil {
		return err
	}
	if s.themeRepo == nil {
		return nil
	}
	return s.themeRepo.DeleteByAppID(app.ID)
}

