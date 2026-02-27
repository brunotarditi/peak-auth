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
	AdminLogin(email, password string) (string, error)
	FindUserByAppID(appID string) ([]response.UserAppRow, error)
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
}

// NewUserService crea una instancia de UserService con las dependencias necesarias.
func NewUserService(userRepo repository.UserRepository, roleRepo repository.RoleRepository, uarRepo repository.UserApplicationRoleRepository, appRepo repository.ApplicationRepository, ruleService ApplicationRuleService, tokenManager *auth.JWTManager, emailVerificationRepo repository.EmailVerificationRepository, passwordResetRepo repository.PasswordResetRepository) UserService {
	return &userService{userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, appRepo: appRepo, ruleService: ruleService, tokenManager: tokenManager, emailVerificationRepo: emailVerificationRepo, passwordResetRepo: passwordResetRepo}
}

// Login valida credenciales, comprueba estado del usuario y genera un token JWT.
func (s *userService) Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error) {
	// 1. Validar Identidad
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil || !utils.CheckPasswordHash(req.Password, user.Password) {
		return response.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	if !user.IsVerified {
		return response.TokenResponse{}, fmt.Errorf("usuario no verificado")
	}

	if !user.IsActive {
		return response.TokenResponse{}, fmt.Errorf("usuario está desactivado")
	}

	// 2. Buscar Aplicación por UUID público (ej: "libreria-mariela" como UUID string)
	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no autorizada")
	}

	// Validar reglas aplicables al login (p.ej. ADMIN_ONLY)
	if err := s.ruleService.ValidateLogin(app.ID, user.ID); err != nil {
		return response.TokenResponse{}, err
	}

	// 4. Generar Token JWT
	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, publicAppID, time.Hour*24)
	if err != nil {
		return response.TokenResponse{}, err
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)

	return response.TokenResponse{AccessToken: token}, nil
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

	// 2) Reglas por app (validateRegistration devuelve defaultRole si existe)
	ruleDefaultRole, err := s.ruleService.ValidateRegistration(app.ID, req)
	if err != nil {
		return model.User{}, err
	}

	// 3) Crear usuario si no existe
	if !userExists {
		nu, _ := req.ToUser()
		profile := model.Profile{FirstName: req.FirstName, LastName: req.LastName}
		if err := s.userRepo.CreateWithProfile(&nu, &profile); err != nil {
			return model.User{}, err
		}
		user = nu
	}

	// 4) Asignar rol por reglas (solo desde reglas: DEFAULT_ROLE)
	assignedRole := ""
	if ruleDefaultRole != "" {
		assignedRole = ruleDefaultRole
	}

	if assignedRole != "" {
		if role, err := s.roleRepo.FindByRoleName(assignedRole); err == nil {
			_ = s.uarRepo.AssignRole(user.ID, app.ID, role.ID)
		}
	}

	// Envío de email ...
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

	if err := sendVerificationEmail("Verificá tu email", user.Email, htmlBody); err != nil {
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

	if err := sendVerificationEmail("Restablecer contraseña", user.Email, htmlBody); err != nil {
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

	return nil
}

func (s *userService) AdminLogin(email, password string) (string, error) {
	user, err := s.userRepo.FindByEmail(email)

	if err != nil {
		return "", fmt.Errorf("credenciales inválidas")
	}

	if !user.IsVerified {
		return "", fmt.Errorf("usuario no verificados")
	}

	if !utils.CheckPasswordHash(password, user.Password) {
		return "", fmt.Errorf("credenciales inválidas")
	}

	peakApp, err := s.appRepo.FindByAppID("peak-auth-raiz")
	if err != nil {
		return "", fmt.Errorf("error de configuración del sistema")
	}

	hasRoot, err := s.uarRepo.HasRole(user.ID, "ROOT")

	if err != nil || !hasRoot {
		return "", fmt.Errorf("no autorizados")
	}

	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, peakApp.AppID, 12*time.Hour)

	if err != nil {
		return "", fmt.Errorf("error generando token: %v", err)
	}

	return token, nil

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
