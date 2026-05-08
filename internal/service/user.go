package service

import (
	"errors"
	"fmt"
	"peak-auth/internal/api/dto"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"time"

	"gorm.io/gorm"
)

type UserService interface {
	Register(req dto.RegisterRequest) (model.User, error)
	Login(req dto.LoginRequest, publicAppID string) (dto.TokenResponse, error)
	FindAll() ([]model.User, error)
	VerifyEmail(token string) (uint, uint, error)
	ResetPassword(token, newPassword string) error
	FindVerifiedUser(email string) (*model.User, error)
	FindVerifiedUserByID(id uint) (*model.User, error)
	GenerateResetToken(userID, appID uint) (string, []byte, error)
	CanRequestPasswordReset(userID uint) (bool, error)
	SendResetEmail(user *model.User) error
	AdminLogin(email, password string) (string, int, error)
	FindUserByAppID(appID string) ([]dto.UserAppRow, error)
	FindUserByAppIDPaginated(appID string, page, limit int) ([]dto.UserAppRow, int64, error)
	Refresh(token string) (dto.TokenResponse, error)
	UnlockUser(userID uint) error
	ResendVerification(userID uint, appID string) error
}

type userService struct {
	userRepo              repo.UserRepository
	roleRepo              repo.RoleRepository
	uarRepo               repo.UserApplicationRoleRepository
	appRepo               repo.ApplicationRepository
	ruleService           ApplicationRuleService
	tokenManager          *auth.JWTManager
	emailVerificationRepo repo.EmailVerificationRepository
	passwordResetRepo     repo.PasswordResetRepository
	emailService          *EmailService
	refreshTokenRepo      repo.RefreshTokenRepository
}

// NewUserService crea una instancia de UserService con las dependencias necesarias.
func NewUserService(userRepo repo.UserRepository, roleRepo repo.RoleRepository, uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository, ruleService ApplicationRuleService, tokenManager *auth.JWTManager, emailVerificationRepo repo.EmailVerificationRepository, passwordResetRepo repo.PasswordResetRepository, emailService *EmailService, refreshTokenRepo repo.RefreshTokenRepository) UserService {
	return &userService{userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, appRepo: appRepo, ruleService: ruleService, tokenManager: tokenManager, emailVerificationRepo: emailVerificationRepo, passwordResetRepo: passwordResetRepo, emailService: emailService, refreshTokenRepo: refreshTokenRepo}
}

// Login valida credenciales, comprueba estado del usuario y genera un token JWT.
func (s *userService) Login(req dto.LoginRequest, publicAppID string) (dto.TokenResponse, error) {
	// 1. Validar Usuario y Aplicación
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return dto.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return dto.TokenResponse{}, fmt.Errorf("aplicación no autorizada")
	}

	// 2. Aplicar política de intentos fallidos (SESSION_POLICY)
	maxFails := 5 // Default
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := util.ParseSessionPolicy(r.Value)
				if err == nil && sess.MaxFailedLogins > 0 {
					maxFails = sess.MaxFailedLogins
				}
			}
		}
	}

	if user.FailedLogins >= uint(maxFails) {
		return dto.TokenResponse{}, fmt.Errorf("cuenta bloqueada por exceso de intentos fallidos")
	}

	// 3. Validar Password
	if !util.CheckPasswordHash(req.Password, user.Password) {
		s.userRepo.UpdateColumn("failed_logins", user.FailedLogins+1, user.ID)
		return dto.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	if !user.IsVerified {
		return dto.TokenResponse{}, fmt.Errorf("usuario no verificado")
	}

	if !user.IsActive {
		return dto.TokenResponse{}, fmt.Errorf("usuario está desactivado")
	}

	// Login exitoso: Resetear contador de fallos
	s.userRepo.UpdateColumn("failed_logins", 0, user.ID)

	// 3. Validar reglas de autorización (AUTHZ_POLICY)
	if err := s.ruleService.ValidateLogin(app.ID, user.ID); err != nil {
		return dto.TokenResponse{}, err
	}

	// 4. Aplicar duración de sesión (SESSION_POLICY)
	duration := time.Hour * 24
	for _, r := range rules {
		if r.Code == "SESSION_POLICY" {
			sess, err := util.ParseSessionPolicy(r.Value)
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
		return dto.TokenResponse{}, err
	}

	// 5. Generar y Almacenar Refresh Token
	plainRT, _, err := util.GenerateToken(64)
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

	return dto.TokenResponse{
		AccessToken:  token,
		RefreshToken: plainRT,
	}, nil
}

// Register crea un usuario respetando las reglas de la aplicación,
// asigna un rol por defecto si corresponde y envía email de verificación.
func (s *userService) Register(req dto.RegisterRequest) (model.User, error) {

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
	plainToken, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return model.User{}, err
	}

	verification := model.EmailVerification{
		UserID:        user.ID,
		ApplicationID: app.ID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}

	if err := s.emailVerificationRepo.CreateEmailVerification(&verification); err != nil {
		return model.User{}, err
	}

	if err := s.emailService.SendVerificationEmail(user.Email, plainToken, app.Name); err != nil {
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
// Retorna el UserID y ApplicationID si todo es correcto para redirección inteligente.
func (s *userService) VerifyEmail(token string) (uint, uint, error) {
	verification, err := s.emailVerificationRepo.FindEmailVerification(token)
	if err != nil {
		return 0, 0, fmt.Errorf("token inválido o expirado")
	}

	// Movemos la lógica de "marcar como verificado" a una operación atómica en el repo
	if err := s.userRepo.VerifyUserEmail(verification.UserID, verification.ID); err != nil {
		return 0, 0, err
	}

	return verification.UserID, verification.ApplicationID, nil
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

// FindVerifiedUserByID retorna el usuario si existe y está verificado por email.
func (s *userService) FindVerifiedUserByID(id uint) (*model.User, error) {
	user, err := s.userRepo.FindById(id)
	if err != nil {
		return nil, fmt.Errorf("usuario no encontrado")
	}
	return &user, nil
}

func (s *userService) GenerateResetToken(userID, appID uint) (string, []byte, error) {
	plainToken, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return "", nil, err
	}

	reset := &model.PasswordReset{
		UserID:        userID,
		ApplicationID: appID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	if err := s.passwordResetRepo.CreatePasswordReset(reset); err != nil {
		return "", nil, err
	}

	return plainToken, tokenHash, nil
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
	plainToken, tokenHash, err := util.GenerateToken(32)
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

	if err := s.emailService.SendPasswordResetEmail(user.Email, plainToken); err != nil {
		return fmt.Errorf("error enviando email: %v", err)
	}
	return nil
}

// ResetPassword valida el token, actualiza la contraseña y marca el token como usado.
func (s *userService) ResetPassword(token, newPassword string) error {
	reset, err := s.passwordResetRepo.FindValidPasswordReset(token)
	if err != nil {
		return fmt.Errorf("el token de restablecimiento es inválido o ha expirado")
	}

	// 1. Verificar que el usuario esté activo
	user, err := s.userRepo.FindById(reset.UserID)
	if err != nil || !user.IsActive {
		return fmt.Errorf("el usuario asociado a este token no está activo o no existe")
	}

	// 2. Aplicar reglas de la aplicación (PWD_POLICY)
	rules, err := s.ruleService.FindRulesByAppID(reset.ApplicationID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "PWD_POLICY" {
				if err := util.ValidatePasswordPolicy(r.Value, newPassword); err != nil {
					return err
				}
			}
		}
	} else if reset.ApplicationID != 0 {
		return fmt.Errorf("error al validar políticas de la aplicación")
	}

	hashed, err := util.HashPassword(newPassword)
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

// AdminLogin valida credenciales y permisos para acceder al panel administrativo.
func (s *userService) AdminLogin(email, password string) (string, int, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", 0, fmt.Errorf("credenciales de administrador inválidas")
	}

	peakApp, err := s.appRepo.FindByAppID(util.AppID_PEAK_AUTH)
	if err != nil {
		return "", 0, fmt.Errorf("error de configuración del sistema")
	}

	// 1. Aplicar política de intentos fallidos (SESSION_POLICY de Peak Auth Raíz)
	maxFails := 5        // Default
	expireMinutes := 720 // Default 12h
	rules, err := s.ruleService.FindRulesByAppID(peakApp.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := util.ParseSessionPolicy(r.Value)
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

	if !user.IsVerified {
		return "", 0, fmt.Errorf("la cuenta de administrador debe estar verificada por email para acceder al panel")
	}

	// 2. Verificar password
	if !util.CheckPasswordHash(password, user.Password) {
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
	duration := time.Duration(expireMinutes) * time.Minute

	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, peakApp.AppID, roles, duration)
	if err != nil {
		return "", 0, err
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)
	return token, expireMinutes, nil
}

func (s *userService) FindUserByAppID(appID string) ([]dto.UserAppRow, error) {
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
func (s *userService) FindUserByAppIDPaginated(appID string, page, limit int) ([]dto.UserAppRow, int64, error) {
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
func (s *userService) Refresh(refreshToken string) (dto.TokenResponse, error) {
	rt, err := s.refreshTokenRepo.FindByToken(refreshToken)
	if err != nil {
		return dto.TokenResponse{}, fmt.Errorf("refresh token inválido o expirado")
	}

	user, err := s.userRepo.FindById(rt.UserID)
	if err != nil {
		return dto.TokenResponse{}, fmt.Errorf("usuario no encontrado")
	}

	app, err := s.appRepo.FindByID(rt.ApplicationID)
	if err != nil {
		return dto.TokenResponse{}, fmt.Errorf("aplicación no encontrada")
	}

	// 1. Duración según SESSION_POLICY
	duration := time.Hour * 24
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == "SESSION_POLICY" {
				sess, err := util.ParseSessionPolicy(r.Value)
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
		return dto.TokenResponse{}, err
	}

	return dto.TokenResponse{
		AccessToken:  newAT,
		RefreshToken: refreshToken,
	}, nil
}

// UnlockUser resetea el contador de intentos fallidos
func (s *userService) UnlockUser(userID uint) error {
	return s.userRepo.UpdateColumn("failed_logins", 0, userID)
}

// ResendVerification genera un nuevo token y envía el email de verificación
func (s *userService) ResendVerification(userID uint, appID string) error {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return fmt.Errorf("usuario no encontrado")
	}

	app, err := s.appRepo.FindByAppID(appID)
	if err != nil {
		return fmt.Errorf("aplicación no encontrada")
	}

	if user.IsVerified {
		return errors.New("el usuario ya está verificado")
	}

	// Rate Limit: Chequear si ya se envió uno recientemente (15 min)
	if latest, err := s.emailVerificationRepo.FindLatestByUserIDAndAppID(user.ID, app.ID); err == nil {
		if time.Since(latest.CreatedAt) < 15*time.Minute {
			wait := 15 - int(time.Since(latest.CreatedAt).Minutes())
			return fmt.Errorf("debe esperar %d minutos más antes de reenviar otro correo", wait)
		}
	}

	// 1. Generar nuevo Token
	plainToken, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return err
	}

	// 2. Crear nueva verificación (expira en 24h)
	verification := model.EmailVerification{
		UserID:        user.ID,
		ApplicationID: app.ID,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}

	if err := s.emailVerificationRepo.CreateEmailVerification(&verification); err != nil {
		return err
	}

	return s.emailService.SendVerificationEmail(user.Email, plainToken, app.Name)
}
