package service

import (
	"errors"
	"fmt"
	"os"
	"peak-auth/auth"
	"peak-auth/model"
	"peak-auth/repository"
	"peak-auth/request"
	"peak-auth/response"
	"peak-auth/utils"
	"time"

	"gorm.io/gorm"
)

type UserService interface {
	Register(req request.RegisterRequest) (model.User, error)
	Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error)
	FindAll() ([]model.User, error)
	VerifyEmail(token string) error
	ResetPassword(token, newPassword string) error
	FindVerifiedUser(email string) (*model.User, error)
	CanRequestPasswordReset(userID uint) (bool, error)
	SendResetEmail(user *model.User) error
	AdminLogin(email, password string) (string, int, error)
	FindUserByAppID(appID string) ([]response.UserAppRow, error)
	FindUserByAppIDPaginated(appID string, page, limit int) ([]response.UserAppRow, int64, error)
	Refresh(token string) (response.TokenResponse, error)
	UnlockUser(userID uint) error
}

type userService struct {
	userRepo              repository.UserRepository
	roleRepo              repository.RoleRepository
	uarRepo               repository.UserApplicationRoleRepository
	appRepo               repository.ApplicationRepository
	ruleService           ApplicationRuleService
	tokenManager          *auth.JWTManager
	emailVerificationRepo repository.EmailVerificationRepository
	passwordResetRepo     repository.PasswordResetRepository
	emailService          *EmailService
	refreshTokenRepo      repository.RefreshTokenRepository
}

// NewUserService crea una instancia de UserService con las dependencias necesarias.
func NewUserService(userRepo repository.UserRepository, roleRepo repository.RoleRepository, uarRepo repository.UserApplicationRoleRepository, appRepo repository.ApplicationRepository, ruleService ApplicationRuleService, tokenManager *auth.JWTManager, emailVerificationRepo repository.EmailVerificationRepository, passwordResetRepo repository.PasswordResetRepository, emailService *EmailService, refreshTokenRepo repository.RefreshTokenRepository) UserService {
	return &userService{userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, appRepo: appRepo, ruleService: ruleService, tokenManager: tokenManager, emailVerificationRepo: emailVerificationRepo, passwordResetRepo: passwordResetRepo, emailService: emailService, refreshTokenRepo: refreshTokenRepo}
}

// Login valida credenciales, comprueba estado del usuario y genera un token JWT.
func (s *userService) Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error) {
	// 1. Validar Usuario y Aplicación
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no autorizada")
	}

	// 2. Aplicar política de intentos fallidos (SESSION_POLICY)
	maxFails := 5 // Default
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := utils.ParseSessionPolicy(r.Value)
				if err == nil && sess.MaxFailedLogins > 0 {
					maxFails = sess.MaxFailedLogins
				}
			}
		}
	}

	if user.FailedLogins >= uint(maxFails) {
		return response.TokenResponse{}, fmt.Errorf("cuenta bloqueada por exceso de intentos fallidos")
	}

	// 3. Validar Password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		s.userRepo.UpdateColumn("failed_logins", user.FailedLogins+1, user.ID)
		return response.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	if !user.IsVerified {
		return response.TokenResponse{}, fmt.Errorf("usuario no verificado")
	}

	if !user.IsActive {
		return response.TokenResponse{}, fmt.Errorf("usuario está desactivado")
	}

	// Login exitoso: Resetear contador de fallos
	s.userRepo.UpdateColumn("failed_logins", 0, user.ID)

	// 3. Validar reglas de autorización (AUTHZ_POLICY)
	if err := s.ruleService.ValidateLogin(app.ID, user.ID); err != nil {
		return response.TokenResponse{}, err
	}

	// 4. Aplicar duración de sesión (SESSION_POLICY)
	duration := time.Hour * 24
	for _, r := range rules {
		if r.Code == "SESSION_POLICY" {
			sess, err := utils.ParseSessionPolicy(r.Value)
			if err == nil && sess.TokenExpirationMinutes > 0 {
				duration = time.Duration(sess.TokenExpirationMinutes) * time.Minute
			}
		}
	}

	// 3.5 Obtener roles para el JWT
	roleModels, _ := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID)
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
	}

	// 4. Generar Token JWT
	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, publicAppID, roles, duration)
	if err != nil {
		return response.TokenResponse{}, err
	}

	// 5. Generar y Almacenar Refresh Token
	plainRT, _, err := utils.GenerateToken(64)
	if err == nil {
		rt := model.RefreshToken{
			UserID:        user.ID,
			ApplicationID: app.ID,
			Token:         plainRT,
			ExpiresAt:     time.Now().Add(7 * 24 * time.Hour), // 7 días
		}
		_ = s.refreshTokenRepo.Create(&rt)
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)

	return response.TokenResponse{
		AccessToken:  token,
		RefreshToken: plainRT,
	}, nil
}

// Register crea un usuario respetando las reglas de la aplicación,
// asigna un rol por defecto si corresponde y envía email de verificación.
func (s *userService) Register(req request.RegisterRequest) (model.User, error) {

	// Verificar app objetivo
	app, err := s.appRepo.FindByAppID(req.AppID)
	if err != nil {
		return model.User{}, fmt.Errorf("aplicación no encontrada")
	}
	// 1) Comprobar si existe un usuario con ese email
	var user model.User
	userExists := false
	u, err := s.userRepo.FindByEmail(req.Email)

	if err == nil {
		user = u
		userExists = true
		// si el usuario ya está asociado a esta app -> error
		if roles, rerr := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID); rerr == nil && len(roles) > 0 {
			return model.User{}, fmt.Errorf("el email ya está registrado en esta aplicación")
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, fmt.Errorf("error verificando usuario: %w", err)
	}

	// 2) Reglas por app (validateRegistration devuelve la política de registro)
	registrationPolicy, err := s.ruleService.ValidateRegistration(app.ID, req)
	if err != nil {
		return model.User{}, err
	}

	// 3) Crear usuario si no existe
	if !userExists {
		nu, _ := req.ToUser()
		profile := model.Profile{FirstName: req.FirstName, LastName: req.LastName}
		
		// Si la política de la app dice que no requiere verificar, lo creamos ya verificado.
		if !registrationPolicy.RequireEmailVerification {
			nu.IsVerified = true
		}

		if err := s.userRepo.CreateWithProfile(&nu, &profile); err != nil {
			return model.User{}, err
		}
		user = nu
	}

	// 4) Asignar rol por reglas
	if registrationPolicy.DefaultRole != "" {
		if role, err := s.roleRepo.FindByRoleName(registrationPolicy.DefaultRole); err == nil {
			_ = s.uarRepo.AssignRole(user.ID, app.ID, role.ID)
		}
	}

	// 5) Si ya está verificado porque la app no lo exige, terminamos acá.
	if user.IsVerified {
		return user, nil
	}

	// 6) Envío de email de verificación...
	plainToken, tokenHash, err := utils.GenerateToken(32)
	if err != nil {
		return model.User{}, err
	}

	verification := model.EmailVerification{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.emailVerificationRepo.CreateEmailVerification(&verification); err != nil {
		return model.User{}, err
	}

	url := os.Getenv("VERIFY_URL")
	verifyURL := fmt.Sprintf(url, plainToken)

	htmlBody, err := utils.RenderVerificationEmail("templates/verify-email.html", map[string]string{
		"VerifyURL": verifyURL,
	})

	if err != nil {
		return model.User{}, fmt.Errorf("error al renderizar email: %w", err)
	}

	if err := s.emailService.Provider.Send("Verificá tu email", user.Email, htmlBody); err != nil {
		return model.User{}, fmt.Errorf("error enviando email: %v", err)
	}

	return user, nil
}

// FindAll devuelve todos los usuarios con su perfil cargado.
func (s *userService) FindAll() ([]model.User, error) {
	users, err := s.userRepo.FindAll()
	if err != nil {
		return nil, fmt.Errorf("error al obtener usuarios: %v", err)
	}
	return users, nil
}

// VerifyEmail verifica el token de email y marca el usuario como verificado.
func (s *userService) VerifyEmail(token string) error {
	verification, err := s.emailVerificationRepo.FindEmailVerification(token)
	if err != nil {
		return fmt.Errorf("token inválido o expirado")
	}

	// Movemos la lógica de "marcar como verificado" a una operación atómica en el repo
	return s.userRepo.VerifyUserEmail(verification.UserID, verification.ID)
}

// FindVerifiedUser retorna el usuario si existe y está verificado por email.
func (s *userService) FindVerifiedUser(email string) (*model.User, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usuario no encontrado")
	}

	if !user.IsVerified {
		return nil, fmt.Errorf("usuario no verificado")
	}
	return &user, nil
}

// CanRequestPasswordReset indica si el usuario puede solicitar un reset (rate-limit).
func (s *userService) CanRequestPasswordReset(userID uint) (bool, error) {
	lastReset, err := s.passwordResetRepo.CheckLastTimeTokenReset(userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, err
	}
	return time.Since(lastReset) >= 15*time.Minute, nil
}

// SendResetEmail crea un token de restablecimiento, lo guarda y envía el email.
func (s *userService) SendResetEmail(user *model.User) error {
	plainToken, tokenHash, err := utils.GenerateToken(32)
	if err != nil {
		return err
	}

	reset := &model.PasswordReset{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := s.passwordResetRepo.CreatePasswordReset(reset); err != nil {
		return err
	}

	verifyURL := fmt.Sprintf(os.Getenv("RESET_PASSWORD"), plainToken)
	htmlBody, err := utils.RenderVerificationEmail("templates/reset-password.html", map[string]string{
		"VerifyURL": verifyURL,
	})
	if err != nil {
		return fmt.Errorf("error al renderizar email: %w", err)
	}

	if err := s.emailService.Provider.Send("Restablecer contraseña", user.Email, htmlBody); err != nil {
		return fmt.Errorf("error enviando email: %v", err)
	}
	return nil
}

// ResetPassword valida el token, actualiza la contraseña y marca el token como usado.
func (s *userService) ResetPassword(token, newPassword string) error {
	reset, err := s.passwordResetRepo.FindValidPasswordReset(token)
	if err != nil {
		return fmt.Errorf("token inválido o expirado")
	}

	// 1. Aplicar reglas de la aplicación (PWD_POLICY)
	rules, err := s.ruleService.FindRulesByAppID(reset.ApplicationID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "PWD_POLICY" {
				if err := utils.ValidatePasswordPolicy(r.Value, newPassword); err != nil {
					return err
				}
			}
		}
	} else if reset.ApplicationID != 0 {
		return fmt.Errorf("error al validar políticas de la aplicación")
	}

	hashed, err := utils.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("error al hashear contraseña: %w", err)
	}

	if err := s.passwordResetRepo.UpdatePassword(reset.UserID, hashed); err != nil {
		return fmt.Errorf("error al actualizar contraseña: %w", err)
	}

	now := time.Now()
	if err := s.passwordResetRepo.MarkPasswordResetUsed(reset.ID, now); err != nil {
		return fmt.Errorf("error al actualizar estado del token: %w", err)
	}

	// Al restablecer (o crear) la contraseña con el token de email, queda verificado implícitamente.
	if err := s.userRepo.UpdateColumn("is_verified", true, reset.UserID); err != nil {
		return fmt.Errorf("error al verificar la cuenta: %w", err)
	}

	return nil
}

func (s *userService) AdminLogin(email, password string) (string, int, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", 0, fmt.Errorf("credenciales de administrador inválidas")
	}

	peakApp, err := s.appRepo.FindByAppID("peak-auth-raiz")
	if err != nil {
		return "", 0, fmt.Errorf("error de configuración del sistema")
	}

	// 1. Aplicar política de intentos fallidos (SESSION_POLICY de Peak Auth Raíz)
	maxFails := 5 // Default
	expireMinutes := 720 // Default 12h
	rules, err := s.ruleService.FindRulesByAppID(peakApp.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := utils.ParseSessionPolicy(r.Value)
				if err == nil {
					if sess.MaxFailedLogins > 0 {
						maxFails = sess.MaxFailedLogins
					}
					if sess.TokenExpirationMinutes > 0 {
						expireMinutes = sess.TokenExpirationMinutes
					}
				}
			}
		}
	}

	if user.FailedLogins >= uint(maxFails) {
		return "", 0, fmt.Errorf("cuenta bloqueada por exceso de intentos fallidos")
	}

	// 2. Verificar password
	if !utils.CheckPasswordHash(password, user.Password) {
		s.userRepo.UpdateColumn("failed_logins", user.FailedLogins+1, user.ID)
		return "", 0, fmt.Errorf("credenciales de administrador inválidas")
	}

	// 3. Validar rol administrativo en Peak Auth Raíz
	roleModels, err := s.uarRepo.FindRolesByUserAndApp(user.ID, peakApp.ID)
	if err != nil || len(roleModels) == 0 {
		return "", 0, fmt.Errorf("el usuario no tiene permisos administrativos")
	}

	isAdmin := false
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
		// ROOT o ADMIN de la app raíz
		if r.Name == "ROOT" || r.Name == "ADMIN" {
			isAdmin = true
		}
	}

	if !isAdmin {
		return "", 0, fmt.Errorf("acceso denegado: se requiere rol ROOT o ADMIN")
	}

	// Limpiar fallos si todo ok
	s.userRepo.UpdateColumn("failed_logins", 0, user.ID)

	// 4. Generar token con la duración de la política
	// La regla SESSION_POLICY.TokenExpirationMinutes está en MINUTOS.
	duration := time.Duration(expireMinutes) * time.Minute
	
	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, peakApp.AppID, roles, duration)
	if err != nil {
		return "", 0, err
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)
	return token, expireMinutes, nil
}

func (s *userService) FindUserByAppID(appID string) ([]response.UserAppRow, error) {
	app, err := s.appRepo.FindByAppID(appID)
	if err != nil {
		return nil, fmt.Errorf("aplicación no encontrada")
	}

	users, err := s.uarRepo.GetUsersWithRolesByApp(app.ID)
	if err != nil {
		return nil, fmt.Errorf("usuarios no encontrados")
	}
	return users, nil
}

// FindUserByAppIDPaginated devuelve los usuarios paginados y el total
func (s *userService) FindUserByAppIDPaginated(appID string, page, limit int) ([]response.UserAppRow, int64, error) {
	app, err := s.appRepo.FindByAppID(appID)
	if err != nil {
		return nil, 0, fmt.Errorf("aplicación no encontrada")
	}

	users, total, err := s.uarRepo.GetUsersWithRolesByAppPaginated(app.ID, page, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("error al obtener usuarios: %v", err)
	}

	return users, total, nil
}

// Refresh valida un refresh token y genera un nuevo access token.
func (s *userService) Refresh(refreshToken string) (response.TokenResponse, error) {
	rt, err := s.refreshTokenRepo.FindByToken(refreshToken)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("refresh token inválido o expirado")
	}

	user, err := s.userRepo.FindById(rt.UserID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("usuario no encontrado")
	}

	app, err := s.appRepo.FindByID(rt.ApplicationID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no encontrada")
	}

	// 1. Duración según SESSION_POLICY
	duration := time.Hour * 24
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := utils.ParseSessionPolicy(r.Value)
				if err == nil && sess.TokenExpirationMinutes > 0 {
					duration = time.Duration(sess.TokenExpirationMinutes) * time.Minute
				}
			}
		}
	}

	// 1.5 Obtener roles para el JWT
	roleModels, _ := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID)
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
	}

	// 2. Generar nuevo Access Token
	newAT, err := s.tokenManager.GenerateToken(user.ID, user.Email, app.AppID, roles, duration)
	if err != nil {
		return response.TokenResponse{}, err
	}

	return response.TokenResponse{
		AccessToken:  newAT,
		RefreshToken: refreshToken,
	}, nil
}

// UnlockUser resetea el contador de intentos fallidos
func (s *userService) UnlockUser(userID uint) error {
	return s.userRepo.UpdateColumn("failed_logins", 0, userID)
}
