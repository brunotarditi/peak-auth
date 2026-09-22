package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"peak-auth/internal/api/request"
	"peak-auth/internal/api/response"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strings"
	"time"

	"gorm.io/gorm"
)

type UserService interface {
	Register(req request.RegisterRequest) (model.User, error)
	Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error)
	FindAll() ([]model.User, error)
	VerifyEmail(token string) (uint, uint, error)
	ResetPassword(token, newPassword string) error
	FindVerifiedUser(email string) (*model.User, error)
	FindVerifiedUserByID(id uint) (*model.User, error)
	GenerateResetToken(userID, appID uint) (string, []byte, error)
	CanRequestPasswordReset(userID uint) (bool, error)
	SendResetEmail(user *model.User, appID uint) error
	AdminLogin(email, password string) (string, int, bool, bool, string, error)
	FindUserByAppID(appID string) ([]response.UserAppRow, error)
	FindUserByAppIDPaginated(appID model.Application, page, limit int) ([]response.UserAppRow, int64, error)
	Refresh(token string) (response.TokenResponse, error)
	UnlockUser(userID uint) error
	ResendVerification(userID uint, appID string) error
	CompleteLoginWithMfa(userID uint, publicAppID string, mfaCompleted bool) (response.TokenResponse, error)
	CompleteAdminLoginWithMfa(userID uint) (string, int, error)
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
	txManager             repo.TransactionManager
}

// NewUserService crea una instancia de UserService con las dependencias necesarias.
func NewUserService(userRepo repo.UserRepository, roleRepo repo.RoleRepository, uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository, ruleService ApplicationRuleService, tokenManager *auth.JWTManager, emailVerificationRepo repo.EmailVerificationRepository, passwordResetRepo repo.PasswordResetRepository, emailService *EmailService, refreshTokenRepo repo.RefreshTokenRepository, txManager repo.TransactionManager) UserService {
	return &userService{userRepo: userRepo, roleRepo: roleRepo, uarRepo: uarRepo, appRepo: appRepo, ruleService: ruleService, tokenManager: tokenManager, emailVerificationRepo: emailVerificationRepo, passwordResetRepo: passwordResetRepo, emailService: emailService, refreshTokenRepo: refreshTokenRepo, txManager: txManager}
}

// resolveTokenDuration safely retrieves and validates the token expiration duration from SESSION_POLICY.
// It fails closed by returning an error if the policy cannot be read or parsed, or if the value is out of bounds.
func (s *userService) resolveTokenDuration(appID uint) (time.Duration, error) {
	rules, err := s.ruleService.FindRulesByAppID(appID)
	if err != nil {
		// Sanitize repository/database errors - do not expose internal details
		return 0, fmt.Errorf("no se pudo obtener la política de sesión")
	}

	for _, r := range rules {
		if r.Code == util.SESSION_POLICY {
			sess, err := util.ValidateSessionPolicy(r.Value)
			if err != nil {
				if _, parseErr := util.ParseSessionPolicy(r.Value); parseErr != nil {
					// Sanitize parser errors - do not expose internal JSON parser details
					return 0, fmt.Errorf("no se pudo interpretar la política de sesión")
				}
				return 0, err
			}
			return time.Duration(sess.TokenExpirationMinutes) * time.Minute, nil
		}
	}

	// No SESSION_POLICY found, use conservative default
	return time.Duration(util.DefaultTokenExpirationMinutes) * time.Minute, nil
}

// Login valida credenciales, comprueba estado del usuario y genera un token JWT.
func (s *userService) Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error) {
	// 1. Validar Usuario y Aplicación
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Mitigación de timing attack y user enumeration
		util.PerformDummyPasswordCheck()
		return response.TokenResponse{}, fmt.Errorf("credenciales inválidas")
	}

	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no autorizada")
	}
	if !app.IsActive {
		return response.TokenResponse{}, fmt.Errorf("la aplicación está desactivada")
	}

	// 2. Aplicar política de intentos fallidos (SESSION_POLICY) (solo si NO es ROOT global)
	isRoot := false
	masterApp, err := s.appRepo.FindByAppID(util.AppIdPeakAuth)
	if err == nil {
		globalRoles, _ := s.uarRepo.GetUserRolesInApp(user.ID, masterApp.ID)
		for _, r := range globalRoles {
			if r == "ROOT" {
				isRoot = true
				break
			}
		}
	}

	maxFails := 5 // Default
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == util.SESSION_POLICY {
				sess, err := util.ParseSessionPolicy(r.Value)
				if err == nil && sess.MaxFailedLogins > 0 {
					maxFails = sess.MaxFailedLogins
				}
			}
		}
	}

	if !isRoot && user.FailedLogins >= uint(maxFails) {
		// Auto-desbloqueo tras 30 días
		if time.Since(user.UpdatedAt) >= 30*24*time.Hour {
			s.userRepo.UpdateColumn("failed_logins", 0, user.ID)
			user.FailedLogins = 0
		} else {
			return response.TokenResponse{}, fmt.Errorf("cuenta bloqueada por exceso de intentos fallidos. Contacte al administrador de la aplicación.")
		}
	}

	// 3. Validar Password
	if !util.CheckPasswordHash(req.Password, user.Password) {
		if !isRoot {
			s.userRepo.UpdateColumn("failed_logins", user.FailedLogins+1, user.ID)
		}
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
	duration, err := s.resolveTokenDuration(app.ID)
	if err != nil {
		return response.TokenResponse{}, err
	}

	// 3.6 Validar MFA_POLICY y MfaEnabled
	mfaRequiredByPolicy := false
	mfaDisabledByPolicy := false
	for _, r := range rules {
		if r.Code == util.MFA_POLICY {
			policy, err := util.ParseMfaPolicy(r.Value)
			if err != nil {
				// Sanitize parser errors - do not expose internal details
				return response.TokenResponse{}, fmt.Errorf("no se pudo interpretar la política de MFA")
			}
			switch policy.Mode {
			case "REQUIRED":
				mfaRequiredByPolicy = true
			case "DISABLED":
				mfaDisabledByPolicy = true
			}
		}
	}

	// Si se requiere por política pero el usuario no tiene MFA habilitado, o si el usuario
	// tiene MFA habilitado y la política no lo prohíbe, detonamos el flujo MFA.
	shouldTriggerMFA := (mfaRequiredByPolicy && !user.MfaEnabled) || (user.MfaEnabled && !mfaDisabledByPolicy)

	if shouldTriggerMFA {
		mfaToken, err := s.tokenManager.GenerateMFAPendingToken(user.ID, user.Email, publicAppID)
		if err != nil {
			// Sanitize token generation errors - do not expose internal details
			return response.TokenResponse{}, fmt.Errorf("error al generar token MFA")
		}
		return response.TokenResponse{
			MfaRequired:      true,
			MfaSetupRequired: !user.MfaEnabled,
			MfaToken:         mfaToken,
		}, nil
	}

	// 3.5 Obtener roles para el JWT
	roleModels, _ := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID)
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
	}

	// 4. Generar Token JWT
	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, publicAppID, roles, duration, false, user.AuthzVersion)
	if err != nil {
		return response.TokenResponse{}, err
	}

	// 5. Generar y Almacenar Refresh Token
	plainRT, rtHash, err := util.GenerateToken(64)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("error al generar el token de acceso")
	}
	rt := model.RefreshToken{
		UserID:        user.ID,
		ApplicationID: app.ID,
		Token:         hex.EncodeToString(rtHash),
		ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
		MfaCompleted:  false,
	}
	createErr := s.refreshTokenRepo.Create(&rt)
	if createErr != nil {
		// Sanitize persistence errors - do not expose database/driver details
		return response.TokenResponse{}, fmt.Errorf("error al generar el refresh token")
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)

	return response.TokenResponse{
		AccessToken:  token,
		RefreshToken: plainRT,
		ExpiresIn:    int(duration.Seconds()),
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
	if !app.IsActive {
		return model.User{}, fmt.Errorf("la aplicación está desactivada")
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

	// 4) Asignar rol por reglas (defensa: jamás asignar ADMIN o ROOT por auto-registro)
	if registrationPolicy.DefaultRole != "" {
		if strings.EqualFold(registrationPolicy.DefaultRole, "ADMIN") || strings.EqualFold(registrationPolicy.DefaultRole, "ROOT") {
			return model.User{}, fmt.Errorf("el registro público no puede otorgar roles administrativos")
		}
		if role, err := s.roleRepo.FindByNameForApp(registrationPolicy.DefaultRole, app.ID); err == nil {
			if assignErr := s.uarRepo.AssignRole(user.ID, app.ID, role.ID); assignErr != nil {
				return model.User{}, fmt.Errorf("error al asignar el rol por defecto: %w", assignErr)
			}
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
	// Hash the token to match against stored hash
	hashedToken := sha256.Sum256([]byte(token))

	// Atomically validate and consume the verification token
	userID, appID, err := s.userRepo.VerifyUserEmailByToken(hashedToken[:])
	if err != nil {
		return 0, 0, fmt.Errorf("token inválido o expirado")
	}

	return userID, appID, nil
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

// FindVerifiedUserByID retorna el usuario si existe, está verificado por email y está activo.
func (s *userService) FindVerifiedUserByID(id uint) (*model.User, error) {
	user, err := s.userRepo.FindById(id)
	if err != nil {
		return nil, fmt.Errorf("usuario no encontrado")
	}

	if !user.IsVerified {
		return nil, fmt.Errorf("usuario no verificado")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("usuario desactivado")
	}

	return &user, nil
}

func (s *userService) GenerateResetToken(userID, appID uint) (string, []byte, error) {
	plainToken, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return "", nil, err
	}

	// Invalidate all previous unused tokens before creating a new one
	if err := s.passwordResetRepo.InvalidateAllUserTokens(userID); err != nil {
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
	if time.Since(lastReset) < 15*time.Minute {
		return false, fmt.Errorf("debe esperar al menos 15 minutos entre solicitudes de reset")
	}

	count, err := s.passwordResetRepo.CountResetsThisMonth(userID)
	if err != nil {
		return false, err
	}
	if count >= 5 {
		return false, fmt.Errorf("límite mensual alcanzado: solo se permiten 5 restablecimientos por mes")
	}

	return true, nil
}

// SendResetEmail atomically checks eligibility, creates a token, and sends the email.
// The eligibility check and reset creation are performed within a transaction with a per-user
// row lock (SELECT ... FOR UPDATE) to serialize concurrent requests and prevent race conditions
// that could bypass cooldown and monthly quota limits.
func (s *userService) SendResetEmail(user *model.User, appID uint) error {
	// Generate token before transaction (expensive cryptographic operation)
	plainToken, tokenHash, err := util.GenerateToken(32)
	if err != nil {
		return err
	}

	// Perform eligibility check and reset creation atomically within a transaction
	if err := s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		// Acquire a row-level lock on the user to serialize concurrent reset requests for this user.
		// This prevents race conditions where multiple concurrent requests could all observe the same
		// eligible state (e.g., 4 resets this month) and then all proceed to insert, bypassing the
		// 5-reset monthly limit. The lock is held until the transaction commits or rolls back.
		if err := tx.Users().LockUserForUpdate(user.ID); err != nil {
			return err
		}

		// Check cooldown: ensure at least 15 minutes since last reset
		lastReset, err := tx.PasswordResets().CheckLastTimeTokenReset(user.ID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && !lastReset.IsZero() && time.Since(lastReset) < 15*time.Minute {
			return fmt.Errorf("debe esperar al menos 15 minutos entre solicitudes de reset")
		}

		// Check monthly quota: ensure fewer than 5 resets this month
		count, err := tx.PasswordResets().CountResetsThisMonth(user.ID)
		if err != nil {
			return err
		}
		if count >= 5 {
			return fmt.Errorf("límite mensual alcanzado: solo se permiten 5 restablecimientos por mes")
		}

		// Invalidate all previous unused tokens before creating a new one
		if err := tx.PasswordResets().InvalidateAllUserTokens(user.ID); err != nil {
			return err
		}

		// Create the new reset token
		reset := &model.PasswordReset{
			UserID:        user.ID,
			ApplicationID: appID,
			TokenHash:     tokenHash,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}
		if err := tx.PasswordResets().CreatePasswordReset(reset); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	// Send email after successful transaction commit
	if s.emailService != nil {
		if err := s.emailService.SendPasswordResetEmail(user.Email, plainToken); err != nil {
			return fmt.Errorf("error enviando email: %v", err)
		}
	}
	return nil
}

// ResetPassword valida el token, actualiza la contraseña y marca el token como
// usado de forma ATÓMICA, e invalida todas las sesiones (refresh tokens) del usuario.
func (s *userService) ResetPassword(token, newPassword string) error {

	// 1. Validate password length early (before expensive operations)
	if err := util.ValidatePasswordLength(newPassword); err != nil {
		return err
	}
	// 2. Hash password before transaction (expensive operation)
	hashed, err := util.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("error al hashear contraseña: %w", err)
	}

	now := time.Now()

	// 3. Execute all operations atomically within a transaction
	return s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		// 3a. Find and validate the reset token inside the transaction
		reset, err := tx.PasswordResets().FindValidPasswordReset(token)
		if err != nil {
			return fmt.Errorf("el token de restablecimiento es inválido o ha expirado")
		}

		// 3b. Verify user is active
		user, err := tx.Users().FindById(reset.UserID)
		if err != nil || !user.IsActive {
			return fmt.Errorf("el usuario asociado a este token no está activo o no existe")
		}

		// 3c. Validate password policy for the application
		rules, err := s.ruleService.FindRulesByAppID(reset.ApplicationID)
		if err == nil {
			policyFound := false
			for _, r := range rules {
				if r.Code == util.PWD_POLICY {
					policyFound = true
					if err := util.ValidatePasswordPolicy(r.Value, newPassword); err != nil {
						return err
					}
				}
			}
			// Enforce minimum password policy when no active PWD_POLICY exists
			// This prevents weak passwords when rules are deleted, deactivated, or misconfigured
			if !policyFound {
				if err := util.ValidateMinimumPasswordPolicy(newPassword); err != nil {
					return err
				}
			}
		} else if reset.ApplicationID != 0 {
			return fmt.Errorf("error al validar políticas de la aplicación")
		}

		// 3d. CRITICAL: Claim the token FIRST (atomic test-and-set)
		// This ensures only one concurrent request can proceed
		if err := tx.PasswordResets().MarkPasswordResetUsed(reset.ID, now); err != nil {
			return fmt.Errorf("el token ya ha sido utilizado o no es válido")
		}

		// 3e. Update password only after successfully claiming the token
		if err := tx.PasswordResets().UpdatePassword(reset.UserID, hashed); err != nil {
			return fmt.Errorf("error al actualizar contraseña: %w", err)
		}

		// 3f. Invalidate all other unused tokens for this user to prevent reuse
		if err := tx.PasswordResets().InvalidateAllUserTokens(reset.UserID); err != nil {
			return fmt.Errorf("error al invalidar tokens previos: %w", err)
		}

		// 3g. Mark user as verified when resetting password via email token
		if err := tx.Users().UpdateColumn("is_verified", true, reset.UserID); err != nil {
			return fmt.Errorf("error al verificar la cuenta: %w", err)
		}

		// 3h. Revoke all existing sessions (refresh tokens) for security
		if err := tx.RefreshTokens().DeleteByUser(reset.UserID); err != nil {
			return fmt.Errorf("error al revocar sesiones: %w", err)
		}

		return nil
	})
}

// AdminLogin valida credenciales y permisos para acceder al panel administrativo.
// To prevent account enumeration, this function always performs password verification
// before checking account state, and returns a generic error message for all failures.
func (s *userService) AdminLogin(email, password string) (string, int, bool, bool, string, error) {
	// Generic error message used for all authentication failures to prevent enumeration
	genericError := fmt.Errorf("las credenciales de administrador son inválidas")

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Mitigación de timing attack y user enumeration
		util.PerformDummyPasswordCheck()
		return "", 0, false, false, "", genericError
	}

	peakApp, err := s.appRepo.FindByAppID(util.AppIdPeakAuth)
	if err != nil {
		return "", 0, false, false, "", fmt.Errorf("error interno del sistema")
	}

	// Get SESSION_POLICY for maxFails (used before password check to prevent enumeration)
	maxFails := 5
	rules, err := s.ruleService.FindRulesByAppID(peakApp.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == util.SESSION_POLICY {
				sess, err := util.ParseSessionPolicy(r.Value)
				if err == nil && sess.MaxFailedLogins > 0 {
					maxFails = sess.MaxFailedLogins
				}
			}
		}
	}

	// 1. Obtener roles en la app raíz (peak-auth) para determinar el alcance de plataforma.
	roleModels, err := s.uarRepo.FindRolesByUserAndApp(user.ID, peakApp.ID)
	canAccessPanel := false
	isRoot := false
	var roles []string

	if err == nil && len(roleModels) > 0 {
		roles = make([]string, len(roleModels))
		for i, r := range roleModels {
			roles[i] = r.Name
			switch r.Name {
			case "ROOT":
				isRoot = true
				canAccessPanel = true
			case "ADMIN":
				// ADMIN en la app raíz = administrador de plataforma.
				canAccessPanel = true
			}
		}
	}

	if !canAccessPanel {
		// Un usuario que es ADMIN de alguna app externa también puede acceder al
		// panel, pero su alcance quedará limitado a sus apps por el middleware y
		// los controllers. No se le inyectan roles globales falsos.
		hasLocalAdmin, err := s.uarRepo.HasAdminRoleInAnyApp(user.ID)
		if err == nil && hasLocalAdmin {
			canAccessPanel = true
		}
	}

	// Store authorization failure but do NOT return yet - check password first
	authzFailed := !canAccessPanel

	// 2. Check lock status but do NOT return yet - check password first
	accountLocked := false
	if !isRoot {
		if user.FailedLogins >= uint(maxFails) {
			if time.Since(user.UpdatedAt) >= 30*24*time.Hour {
				// Auto-unlock after 30 days
				s.userRepo.UpdateColumn("failed_logins", 0, user.ID)
				user.FailedLogins = 0
			} else {
				accountLocked = true
			}
		}
	}

	// Store account state but do NOT return yet - check password first
	accountInactive := !user.IsActive
	accountUnverified := !user.IsVerified

	// 3. ALWAYS verify password regardless of account state to prevent timing attacks and enumeration
	passwordValid := util.CheckPasswordHash(password, user.Password)

	// 4. Now check all failure conditions AFTER password verification
	if !passwordValid {
		if !isRoot {
			s.userRepo.UpdateColumn("failed_logins", user.FailedLogins+1, user.ID)
		}
		return "", 0, false, false, "", genericError
	}

	// Password is valid - now check authorization and account state
	if authzFailed {
		return "", 0, false, false, "", genericError
	}

	if accountLocked {
		return "", 0, false, false, "", genericError
	}

	if accountInactive {
		return "", 0, false, false, "", genericError
	}

	if accountUnverified {
		return "", 0, false, false, "", genericError
	}

	// All checks passed - reset failed login counter
	s.userRepo.UpdateColumn("failed_logins", 0, user.ID)

	// Validar MFA_POLICY para la app de administración (peak-auth)
	mfaRequiredByPolicy := false
	mfaDisabledByPolicy := false
	for _, r := range rules {
		if r.Code == util.MFA_POLICY {
			policy, err := util.ParseMfaPolicy(r.Value)
			if err != nil {
				// Sanitize parser errors - do not expose internal details
				return "", 0, false, false, "", fmt.Errorf("no se pudo interpretar la política de MFA")
			}
			switch policy.Mode {
			case "REQUIRED":
				mfaRequiredByPolicy = true
			case "DISABLED":
				mfaDisabledByPolicy = true
			}
		}
	}

	shouldTriggerMFA := (mfaRequiredByPolicy && !user.MfaEnabled) || (user.MfaEnabled && !mfaDisabledByPolicy)

	// Resolve token duration with fail-closed behavior
	duration, err := s.resolveTokenDuration(peakApp.ID)
	if err != nil {
		return "", 0, false, false, "", err
	}
	expireMinutes := int(duration.Minutes())

	if shouldTriggerMFA {
		mfaToken, err := s.tokenManager.GenerateMFAPendingToken(user.ID, user.Email, peakApp.AppID)
		if err != nil {
			return "", 0, false, false, "", err
		}
		return "", expireMinutes, true, !user.MfaEnabled, mfaToken, nil
	}

	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, peakApp.AppID, roles, duration, true, user.AuthzVersion)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return "", 0, false, false, "", fmt.Errorf("error al generar el token de acceso")
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)
	return token, expireMinutes, false, false, "", nil
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
func (s *userService) FindUserByAppIDPaginated(app model.Application, page, limit int) ([]response.UserAppRow, int64, error) {
	users, total, err := s.uarRepo.GetUsersWithRolesByAppPaginated(app.ID, page, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("error al obtener usuarios: %v", err)
	}

	return users, total, nil
}

// Refresh valida un refresh token y genera un nuevo access token.
func (s *userService) Refresh(refreshToken string) (response.TokenResponse, error) {
	hash := sha256.Sum256([]byte(refreshToken))
	tokenHashStr := hex.EncodeToString(hash[:])

	rt, err := s.refreshTokenRepo.FindByToken(tokenHashStr)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("refresh token inválido o expirado")
	}

	user, err := s.userRepo.FindById(rt.UserID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("usuario no encontrado")
	}

	if !user.IsActive {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, fmt.Errorf("usuario desactivado")
	}

	if !user.IsVerified {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, fmt.Errorf("usuario no verificado")
	}

	app, err := s.appRepo.FindByID(rt.ApplicationID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no encontrada")
	}

	if !app.IsActive {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, fmt.Errorf("la aplicación está desactivada")
	}

	// Validar que el usuario siga teniendo acceso y reglas vigentes en la aplicación
	if err := s.ruleService.ValidateLogin(app.ID, user.ID); err != nil {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, err
	}

	// 1. Duración según SESSION_POLICY
	duration, err := s.resolveTokenDuration(app.ID)
	if err != nil {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, err
	}

	// 1.5 Obtener roles para el JWT
	roleModels, _ := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID)
	if len(roleModels) == 0 {
		_ = s.refreshTokenRepo.DeleteByToken(tokenHashStr)
		return response.TokenResponse{}, fmt.Errorf("el usuario no tiene acceso a esta aplicación")
	}
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
	}

	// 2. Generar nuevo Access Token preservando el aseguramiento de MFA original
	newAT, err := s.tokenManager.GenerateToken(user.ID, user.Email, app.AppID, roles, duration, rt.MfaCompleted, user.AuthzVersion)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("error al generar el token de acceso")
	}

	// 3. Generar nuevo Refresh Token ANTES de borrar el viejo.
	plainRT, rtHash, err := util.GenerateToken(64)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("error al generar el refresh token")
	}

	newRtModel := model.RefreshToken{
		UserID:        user.ID,
		ApplicationID: app.ID,
		Token:         hex.EncodeToString(rtHash),
		ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
		MfaCompleted:  rt.MfaCompleted,
	}

	// 4. Rotación atómica: consumir el token viejo (verificando que se elimine exactamente 1 fila)
	// y persistir el nuevo en una transacción. Esto previene que solicitudes concurrentes
	// con el mismo refresh token puedan ambas tener éxito.
	if err := s.txManager.WithinTransaction(func(tx repo.TxRepository) error {
		rowsAffected, err := tx.RefreshTokens().DeleteByTokenAtomic(tokenHashStr)
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("refresh token ya fue usado o expiró")
		}
		return tx.RefreshTokens().Create(&newRtModel)
	}); err != nil {
		// Sanitize transaction/persistence errors - do not expose database/driver details
		return response.TokenResponse{}, fmt.Errorf("error al rotar el refresh token")
	}

	return response.TokenResponse{
		AccessToken:  newAT,
		RefreshToken: plainRT,
		ExpiresIn:    int(duration.Seconds()),
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

func (s *userService) CompleteLoginWithMfa(userID uint, publicAppID string, mfaCompleted bool) (response.TokenResponse, error) {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("usuario no encontrado")
	}

	if !user.IsActive {
		return response.TokenResponse{}, fmt.Errorf("usuario desactivado")
	}

	if !user.IsVerified {
		return response.TokenResponse{}, fmt.Errorf("usuario no verificado")
	}

	app, err := s.appRepo.FindByAppID(publicAppID)
	if err != nil {
		return response.TokenResponse{}, fmt.Errorf("aplicación no encontrada")
	}
	if !app.IsActive {
		return response.TokenResponse{}, fmt.Errorf("la aplicación está desactivada")
	}

	// 1. Validar reglas de autorización (AUTHZ_POLICY)
	if err := s.ruleService.ValidateLogin(app.ID, user.ID); err != nil {
		// Sanitize authorization rule errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("no se pudo validar el acceso del usuario")
	}

	// 2. Aplicar duración de sesión (SESSION_POLICY) y validar MFA_POLICY
	duration, err := s.resolveTokenDuration(app.ID)
	if err != nil {
		return response.TokenResponse{}, err
	}

	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err != nil {
		// Sanitize repository/database errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("no se pudo obtener las reglas de la aplicación")
	}

	for _, r := range rules {
		if r.Code == util.MFA_POLICY {
			mfaPol, err := util.ParseMfaPolicy(r.Value)
			if err != nil {
				// Sanitize parser errors - do not expose internal details
				return response.TokenResponse{}, fmt.Errorf("no se pudo interpretar la política de MFA")
			}
			if mfaPol.Mode == "REQUIRED" {
				if !user.MfaEnabled {
					return response.TokenResponse{}, fmt.Errorf("la aplicación requiere autenticación multi-factor (MFA)")
				}
				if !mfaCompleted {
					return response.TokenResponse{}, fmt.Errorf("la aplicación requiere completar autenticación multi-factor (MFA)")
				}
			}
		}
	}

	// 3. Obtener roles para el JWT
	roleModels, _ := s.uarRepo.FindRolesByUserAndApp(user.ID, app.ID)
	if len(roleModels) == 0 {
		return response.TokenResponse{}, fmt.Errorf("el usuario no tiene acceso a esta aplicación")
	}
	roles := make([]string, len(roleModels))
	for i, r := range roleModels {
		roles[i] = r.Name
	}

	// 4. Generar Token JWT
	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, publicAppID, roles, duration, mfaCompleted, user.AuthzVersion)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("error al generar el token de acceso")
	}

	// 5. Generar y Almacenar Refresh Token
	plainRT, rtHash, err := util.GenerateToken(64)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return response.TokenResponse{}, fmt.Errorf("error al generar el refresh token")
	}
	rt := model.RefreshToken{
		UserID:        user.ID,
		ApplicationID: app.ID,
		Token:         hex.EncodeToString(rtHash),
		ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
		MfaCompleted:  mfaCompleted,
	}
	if err := s.refreshTokenRepo.Create(&rt); err != nil {
		// Sanitize persistence errors - do not expose database/driver details
		return response.TokenResponse{}, fmt.Errorf("error al generar el refresh token")
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)

	return response.TokenResponse{
		AccessToken:  token,
		RefreshToken: plainRT,
		ExpiresIn:    int(duration.Seconds()),
	}, nil
}

func (s *userService) CompleteAdminLoginWithMfa(userID uint) (string, int, error) {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return "", 0, fmt.Errorf("usuario no encontrado")
	}

	if !user.IsActive {
		return "", 0, fmt.Errorf("usuario desactivado")
	}

	if !user.IsVerified {
		return "", 0, fmt.Errorf("usuario no verificado")
	}

	peakApp, err := s.appRepo.FindByAppID(util.AppIdPeakAuth)
	if err != nil {
		return "", 0, fmt.Errorf("error interno del sistema")
	}

	duration, err := s.resolveTokenDuration(peakApp.ID)
	if err != nil {
		return "", 0, err
	}
	expireMinutes := int(duration.Minutes())

	roleModels, err := s.uarRepo.FindRolesByUserAndApp(user.ID, peakApp.ID)
	var roles []string
	canAccessPanel := false
	if err == nil && len(roleModels) > 0 {
		roles = make([]string, len(roleModels))
		for i, r := range roleModels {
			roles[i] = r.Name
			if r.Name == "ROOT" || r.Name == "ADMIN" {
				canAccessPanel = true
			}
		}
	}

	if !canAccessPanel {
		hasLocalAdmin, err := s.uarRepo.HasAdminRoleInAnyApp(user.ID)
		if err == nil && hasLocalAdmin {
			canAccessPanel = true
		}
	}

	if !canAccessPanel {
		return "", 0, fmt.Errorf("el usuario no tiene permisos administrativos")
	}

	token, err := s.tokenManager.GenerateToken(user.ID, user.Email, peakApp.AppID, roles, duration, true, user.AuthzVersion)
	if err != nil {
		// Sanitize token generation errors - do not expose internal details
		return "", 0, fmt.Errorf("error al generar el token de acceso")
	}

	s.userRepo.UpdateColumn("last_login", time.Now(), user.ID)
	return token, expireMinutes, nil
}
