package service

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"peak-auth/internal/api/request"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"gorm.io/gorm"
)

// --- Tests User Service ---

func TestAdminLogin_RejectsDeactivatedUser(t *testing.T) {
	// Hash for password "testpass123"
	hashedPassword, _ := util.HashPassword("testpass123")

	userRepo := &mockUserRepo{
		user: model.User{
			Email:      "admin@peak.test",
			Password:   hashedPassword,
			IsActive:   false,
			IsVerified: true,
		},
	}
	appRepo := newMockAppRepo()
	peakApp := &model.Application{Name: "Peak Auth", AppID: util.AppIdPeakAuth}
	appRepo.apps[util.AppIdPeakAuth] = peakApp

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{0: {"ADMIN"}},
	}
	ruleSvc := NewApplicationRuleService(&mockRuleRepo{}, uarRepo, nil, appRepo)

	svc := &userService{
		userRepo:    userRepo,
		appRepo:     appRepo,
		uarRepo:     uarRepo,
		ruleService: ruleSvc,
	}

	// Test with correct password - should return generic error to prevent enumeration
	_, _, _, _, _, err := svc.AdminLogin("admin@peak.test", "testpass123")
	if err == nil || err.Error() != "las credenciales de administrador son inválidas" {
		t.Fatalf("Esperaba error genérico para prevenir enumeración, pero obtuvo: %v", err)
	}
}

func TestAdminLogin_RejectsNonAdminUserWithGenericError(t *testing.T) {
	hashedPassword, _ := util.HashPassword("testpass123")

	userRepo := &mockUserRepo{
		user: model.User{
			Email:      "regular@peak.test",
			Password:   hashedPassword,
			IsActive:   true,
			IsVerified: true,
		},
	}
	appRepo := newMockAppRepo()
	peakApp := &model.Application{Name: "Peak Auth", AppID: util.AppIdPeakAuth}
	appRepo.apps[util.AppIdPeakAuth] = peakApp

	// Usuario sin roles administrativos
	noAdmin := false
	uarRepo := &mockUARRepo{
		roles:                map[uint][]string{0: {"USER"}},
		hasAdminRoleInAnyApp: &noAdmin,
	}
	ruleSvc := NewApplicationRuleService(&mockRuleRepo{}, uarRepo, nil, appRepo)

	svc := &userService{
		userRepo:    userRepo,
		appRepo:     appRepo,
		uarRepo:     uarRepo,
		ruleService: ruleSvc,
	}

	// Debe retornar el error genérico sin filtrar si es o no admin
	_, _, _, _, _, err := svc.AdminLogin("regular@peak.test", "testpass123")
	if err == nil || err.Error() != "las credenciales de administrador son inválidas" {
		t.Fatalf("Esperaba error genérico para usuario no-admin, pero obtuvo: %v", err)
	}
}

func TestCompleteLoginWithMfa_RejectsDeactivatedUser(t *testing.T) {
	userRepo := &mockUserRepo{
		user: model.User{
			Email:      "user@test.com",
			IsActive:   false,
			IsVerified: true,
		},
	}

	svc := &userService{
		userRepo: userRepo,
	}

	_, err := svc.CompleteLoginWithMfa(1, "my-app", true)
	if err == nil || err.Error() != "usuario desactivado" {
		t.Fatalf("Esperaba error 'usuario desactivado', pero obtuvo: %v", err)
	}
}

func TestCompleteAdminLoginWithMfa_RejectsDeactivatedUser(t *testing.T) {
	userRepo := &mockUserRepo{
		user: model.User{
			Email:      "admin@peak.test",
			IsActive:   false,
			IsVerified: true,
		},
	}

	svc := &userService{
		userRepo: userRepo,
	}

	_, _, err := svc.CompleteAdminLoginWithMfa(1)
	if err == nil || err.Error() != "usuario desactivado" {
		t.Fatalf("Esperaba error 'usuario desactivado', pero obtuvo: %v", err)
	}
}


func TestCompleteLoginWithMfa_RejectsWhenAppRequiresMfaAndUserHasNoMfa(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["secure-app"] = &model.Application{
		Model:    gorm.Model{ID: 10},
		AppID:    "secure-app",
		IsActive: true,
	}

	userRepo := &mockUserRepo{
		user: model.User{
			Model:      gorm.Model{ID: 1},
			Email:      "user@test.com",
			IsActive:   true,
			IsVerified: true,
			MfaEnabled: false,
		},
	}

	svc := &userService{
		userRepo: userRepo,
		appRepo:  appRepo,
		ruleService: &mockRuleServiceForMfa{
			rules: []model.ApplicationRules{
				{
					ApplicationID: 10,
					Code:          "MFA_POLICY",
					Value:         []byte(`{"mode":"REQUIRED"}`),
				},
			},
		},
	}

	_, err := svc.CompleteLoginWithMfa(1, "secure-app", false)
	if err == nil || !strings.Contains(err.Error(), "la aplicación requiere autenticación multi-factor (MFA)") {
		t.Fatalf("Esperaba error de requerimiento de MFA, obtuvo: %v", err)
	}
}

func TestCompleteLoginWithMfa_RejectsWhenAppRequiresMfaAndMfaNotCompleted(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["secure-app"] = &model.Application{
		Model:    gorm.Model{ID: 10},
		AppID:    "secure-app",
		IsActive: true,
	}

	userRepo := &mockUserRepo{
		user: model.User{
			Model:      gorm.Model{ID: 1},
			Email:      "user@test.com",
			IsActive:   true,
			IsVerified: true,
			MfaEnabled: true,
		},
	}

	svc := &userService{
		userRepo: userRepo,
		appRepo:  appRepo,
		ruleService: &mockRuleServiceForMfa{
			rules: []model.ApplicationRules{
				{
					ApplicationID: 10,
					Code:          "MFA_POLICY",
					Value:         []byte(`{"mode":"REQUIRED"}`),
				},
			},
		},
	}

	_, err := svc.CompleteLoginWithMfa(1, "secure-app", false)
	if err == nil || !strings.Contains(err.Error(), "la aplicación requiere completar autenticación multi-factor (MFA)") {
		t.Fatalf("Esperaba error de completar MFA, obtuvo: %v", err)
	}
}

func TestRegister_ForbidsAdminAndRootRole(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app", IsActive: true}

	svc := &userService{
		appRepo:  appRepo,
		userRepo: &mockUserRepo{err: gorm.ErrRecordNotFound},
		uarRepo:  &mockUARRepo{},
		ruleService: &mockRuleServiceForRegister{
			policy: &util.RegistrationPolicy{
				Mode:        "public",
				DefaultRole: "ADMIN",
			},
		},
	}

	_, err := svc.Register(request.RegisterRequest{
		Email: "new@test.com",
		AppID: "my-app",
	})
	if err == nil || !strings.Contains(err.Error(), "no puede otorgar roles administrativos") {
		t.Fatalf("Esperaba bloqueo de rol administrativo en Register, obtuvo: %v", err)
	}
}

func TestDeactivatedApp_RejectsLoginAndRegister(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["inactive-app"] = &model.Application{
		Model:    gorm.Model{ID: 5},
		AppID:    "inactive-app",
		IsActive: false,
	}

	svc := &userService{
		appRepo:  appRepo,
		userRepo: &mockUserRepo{user: model.User{IsActive: true, IsVerified: true}},
	}

	// Login
	passHash, _ := util.HashPassword("Password123!")
	svc.userRepo = &mockUserRepo{user: model.User{Password: passHash, IsActive: true, IsVerified: true}}
	_, err := svc.Login(request.LoginRequest{Email: "user@test.com", Password: "Password123!"}, "inactive-app")
	if err == nil || !strings.Contains(err.Error(), "la aplicación está desactivada") {
		t.Fatalf("Esperaba error de aplicación desactivada en Login, obtuvo: %v", err)
	}

	// Register
	_, err = svc.Register(request.RegisterRequest{Email: "user@test.com", AppID: "inactive-app"})
	if err == nil || !strings.Contains(err.Error(), "la aplicación está desactivada") {
		t.Fatalf("Esperaba error de aplicación desactivada en Register, obtuvo: %v", err)
	}

	// CompleteLoginWithMfa
	_, err = svc.CompleteLoginWithMfa(1, "inactive-app", false)
	if err == nil || !strings.Contains(err.Error(), "la aplicación está desactivada") {
		t.Fatalf("Esperaba error de aplicación desactivada en CompleteLoginWithMfa, obtuvo: %v", err)
	}
}


// --- Tests Refresh Token Rotation & Replay Prevention ---

func newServiceTestJWTManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error al generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	tm, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("error creando TokenManager: %v", err)
	}
	return tm
}

func TestRefreshToken_AtomicRotation_And_ReplayPrevention(t *testing.T) {
	tm := newServiceTestJWTManager(t)

	user := model.User{
		ID:         7,
		Email:      "active@peak.test",
		IsActive:   true,
		IsVerified: true,
	}
	userRepo := &mockUserRepo{user: user}

	app := model.Application{
		ID:          1,
		AppID:       "test-app",
		Name:        "Test App",
		IsActive:    true,
		RedirectURL: "https://test.com/cb",
	}
	appRepo := newMockAppRepo()
	appRepo.apps["test-app"] = &app

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{7: {"USER"}},
	}
	ruleSvc := NewApplicationRuleService(&mockRuleRepo{}, uarRepo, nil, appRepo)

	refreshRepo := newMockRefreshTokenRepo()
	txMgr := &mockTxManager{txRepo: &mockTxRepo{refreshRepo: refreshRepo}}

	// Generar token inicial
	initialPlainToken := "initial_plain_refresh_token_1234567890"
	initialHash := sha256.Sum256([]byte(initialPlainToken))
	initialHashStr := hex.EncodeToString(initialHash[:])

	_ = refreshRepo.Create(&model.RefreshToken{
		UserID:        user.ID,
		ApplicationID: app.ID,
		Token:         initialHashStr,
		ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
	})

	svc := &userService{
		userRepo:         userRepo,
		appRepo:          appRepo,
		uarRepo:          uarRepo,
		ruleService:      ruleSvc,
		tokenManager:     tm,
		refreshTokenRepo: refreshRepo,
		txManager:        txMgr,
	}

	// 1. Canje válido del refresh token
	resp1, err := svc.Refresh(initialPlainToken)
	if err != nil {
		t.Fatalf("Refresh válido falló: %v", err)
	}
	if resp1.AccessToken == "" {
		t.Fatalf("se esperaba nuevo AccessToken devuelto")
	}
	if resp1.RefreshToken == "" || resp1.RefreshToken == initialPlainToken {
		t.Fatalf("se esperaba nuevo RefreshToken distinto al inicial")
	}

	// 2. Comprobar que el token inicial fue eliminado de la base de datos (rotación)
	if _, err := refreshRepo.FindByToken(initialHashStr); err == nil {
		t.Fatalf("el refresh token inicial debió haberse eliminado de la BD tras la rotación")
	}

	// 3. Comprobar que el nuevo token fue persistido
	newHash := sha256.Sum256([]byte(resp1.RefreshToken))
	newHashStr := hex.EncodeToString(newHash[:])
	if _, err := refreshRepo.FindByToken(newHashStr); err != nil {
		t.Fatalf("el nuevo refresh token debió haberse persistido en la BD: %v", err)
	}

	// 4. PROTECCIÓN CONTRA REPLAY: Reintentar refrescar con el token viejo ya rotado DEBE fallar
	_, err = svc.Refresh(initialPlainToken)
	if err == nil || !strings.Contains(err.Error(), "refresh token inválido o expirado") {
		t.Fatalf("se esperaba error 'refresh token inválido o expirado' al reutilizar token viejo, obtenido: %v", err)
	}

	// 5. El nuevo token puede volver a rotar exitosamente
	resp2, err := svc.Refresh(resp1.RefreshToken)
	if err != nil {
		t.Fatalf("rotación con el nuevo token falló: %v", err)
	}
	if resp2.RefreshToken == resp1.RefreshToken {
		t.Fatalf("se esperaba rotación a un tercer refresh token distinto")
	}
}

func TestRefreshToken_InactiveOrUnverifiedUser(t *testing.T) {
	tm := newServiceTestJWTManager(t)

	app := model.Application{
		ID:          1,
		AppID:       "test-app",
		Name:        "Test App",
		IsActive:    true,
		RedirectURL: "https://test.com/cb",
	}
	appRepo := newMockAppRepo()
	appRepo.apps["test-app"] = &app

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{7: {"USER"}},
	}
	ruleSvc := NewApplicationRuleService(&mockRuleRepo{}, uarRepo, nil, appRepo)

	// Caso A: Usuario desactivado
	inactiveUser := model.User{
		ID:         7,
		Email:      "inactive@peak.test",
		IsActive:   false,
		IsVerified: true,
	}
	refreshRepoA := newMockRefreshTokenRepo()
	plainTokenA := "token_inactive_user"
	hashA := sha256.Sum256([]byte(plainTokenA))
	hashAStr := hex.EncodeToString(hashA[:])
	_ = refreshRepoA.Create(&model.RefreshToken{UserID: 7, ApplicationID: 1, Token: hashAStr})

	svcA := &userService{
		userRepo:         &mockUserRepo{user: inactiveUser},
		appRepo:          appRepo,
		uarRepo:          uarRepo,
		ruleService:      ruleSvc,
		tokenManager:     tm,
		refreshTokenRepo: refreshRepoA,
		txManager:        &mockTxManager{txRepo: &mockTxRepo{refreshRepo: refreshRepoA}},
	}

	_, err := svcA.Refresh(plainTokenA)
	if err == nil || !strings.Contains(err.Error(), "usuario desactivado") {
		t.Fatalf("se esperaba 'usuario desactivado', obtenido: %v", err)
	}
	if _, err := refreshRepoA.FindByToken(hashAStr); err == nil {
		t.Fatalf("el token del usuario desactivado debió ser eliminado")
	}

	// Caso B: Usuario no verificado
	unverifiedUser := model.User{
		ID:         8,
		Email:      "unverified@peak.test",
		IsActive:   true,
		IsVerified: false,
	}
	refreshRepoB := newMockRefreshTokenRepo()
	plainTokenB := "token_unverified_user"
	hashB := sha256.Sum256([]byte(plainTokenB))
	hashBStr := hex.EncodeToString(hashB[:])
	_ = refreshRepoB.Create(&model.RefreshToken{UserID: 8, ApplicationID: 1, Token: hashBStr})

	svcB := &userService{
		userRepo:         &mockUserRepo{user: unverifiedUser},
		appRepo:          appRepo,
		uarRepo:          &mockUARRepo{roles: map[uint][]string{8: {"USER"}}},
		ruleService:      ruleSvc,
		tokenManager:     tm,
		refreshTokenRepo: refreshRepoB,
		txManager:        &mockTxManager{txRepo: &mockTxRepo{refreshRepo: refreshRepoB}},
	}

	_, err = svcB.Refresh(plainTokenB)
	if err == nil || !strings.Contains(err.Error(), "usuario no verificado") {
		t.Fatalf("se esperaba 'usuario no verificado', obtenido: %v", err)
	}
	if _, err := refreshRepoB.FindByToken(hashBStr); err == nil {
		t.Fatalf("el token del usuario no verificado debió ser eliminado")
	}
}

func TestRefreshToken_PreservesMfaAssuranceLevel(t *testing.T) {
	tm := newServiceTestJWTManager(t)

	user := model.User{
		ID:         10,
		Email:      "mfa-user@peak.test",
		IsActive:   true,
		IsVerified: true,
	}
	userRepo := &mockUserRepo{user: user}

	app := model.Application{
		ID:          1,
		AppID:       "test-app",
		Name:        "Test App",
		IsActive:    true,
		RedirectURL: "https://test.com/cb",
	}
	appRepo := newMockAppRepo()
	appRepo.apps["test-app"] = &app

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{10: {"USER"}},
	}
	ruleSvc := NewApplicationRuleService(&mockRuleRepo{}, uarRepo, nil, appRepo)

	t.Run("Token emitido sin MFA preserva mfa_verified=false tras refresco", func(t *testing.T) {
		refreshRepo := newMockRefreshTokenRepo()
		txMgr := &mockTxManager{txRepo: &mockTxRepo{refreshRepo: refreshRepo}}

		plainToken := "plain_without_mfa_12345"
		hash := sha256.Sum256([]byte(plainToken))
		hashStr := hex.EncodeToString(hash[:])

		_ = refreshRepo.Create(&model.RefreshToken{
			UserID:        user.ID,
			ApplicationID: app.ID,
			Token:         hashStr,
			ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			MfaCompleted:  false,
		})

		svc := &userService{
			userRepo:         userRepo,
			appRepo:          appRepo,
			uarRepo:          uarRepo,
			ruleService:      ruleSvc,
			tokenManager:     tm,
			refreshTokenRepo: refreshRepo,
			txManager:        txMgr,
		}

		resp, err := svc.Refresh(plainToken)
		if err != nil {
			t.Fatalf("Refresh falló: %v", err)
		}

		claims, err := tm.VerifyToken(resp.AccessToken)
		if err != nil {
			t.Fatalf("Error verificando claims del AccessToken: %v", err)
		}
		if claims.MfaVerified {
			t.Fatalf("VULNERABILIDAD DETECTADA: el AccessToken resultante tiene mfa_verified=true cuando el token original fue sin MFA")
		}

		// Verificar que el nuevo refresh token rotado mantiene MfaCompleted=false
		newHash := sha256.Sum256([]byte(resp.RefreshToken))
		newHashStr := hex.EncodeToString(newHash[:])
		newRt, err := refreshRepo.FindByToken(newHashStr)
		if err != nil {
			t.Fatalf("No se encontró el nuevo refresh token en repo: %v", err)
		}
		if newRt.MfaCompleted {
			t.Fatalf("El nuevo RefreshToken debió persistir MfaCompleted=false")
		}
	})

	t.Run("Token emitido con MFA preserva mfa_verified=true tras refresco", func(t *testing.T) {
		refreshRepo := newMockRefreshTokenRepo()
		txMgr := &mockTxManager{txRepo: &mockTxRepo{refreshRepo: refreshRepo}}

		plainToken := "plain_with_mfa_67890"
		hash := sha256.Sum256([]byte(plainToken))
		hashStr := hex.EncodeToString(hash[:])

		_ = refreshRepo.Create(&model.RefreshToken{
			UserID:        user.ID,
			ApplicationID: app.ID,
			Token:         hashStr,
			ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			MfaCompleted:  true,
		})

		svc := &userService{
			userRepo:         userRepo,
			appRepo:          appRepo,
			uarRepo:          uarRepo,
			ruleService:      ruleSvc,
			tokenManager:     tm,
			refreshTokenRepo: refreshRepo,
			txManager:        txMgr,
		}

		resp, err := svc.Refresh(plainToken)
		if err != nil {
			t.Fatalf("Refresh falló: %v", err)
		}

		claims, err := tm.VerifyToken(resp.AccessToken)
		if err != nil {
			t.Fatalf("Error verificando claims del AccessToken: %v", err)
		}
		if !claims.MfaVerified {
			t.Fatalf("Se esperaba mfa_verified=true para sesión con MFA completado")
		}

		// Verificar que el nuevo refresh token rotado mantiene MfaCompleted=true
		newHash := sha256.Sum256([]byte(resp.RefreshToken))
		newHashStr := hex.EncodeToString(newHash[:])
		newRt, err := refreshRepo.FindByToken(newHashStr)
		if err != nil {
			t.Fatalf("No se encontró el nuevo refresh token en repo: %v", err)
		}
		if !newRt.MfaCompleted {
			t.Fatalf("El nuevo RefreshToken debió persistir MfaCompleted=true")
		}
	})
}

func TestUserService_FindVerifiedUserByID(t *testing.T) {
	t.Run("Usuario activo y verificado retorna usuario exitosamente", func(t *testing.T) {
		repo := &mockUserRepo{
			user: model.User{
				Email:      "active@test.com",
				IsActive:   true,
				IsVerified: true,
			},
		}
		svc := &userService{userRepo: repo}
		user, err := svc.FindVerifiedUserByID(1)
		if err != nil {
			t.Fatalf("se esperaba éxito, obtenido error: %v", err)
		}
		if user.Email != "active@test.com" {
			t.Errorf("email esperado 'active@test.com', obtenido: %s", user.Email)
		}
	})

	t.Run("Usuario no verificado es rechazado", func(t *testing.T) {
		repo := &mockUserRepo{
			user: model.User{
				Email:      "unverified@test.com",
				IsActive:   true,
				IsVerified: false,
			},
		}
		svc := &userService{userRepo: repo}
		user, err := svc.FindVerifiedUserByID(1)
		if err == nil {
			t.Fatalf("se esperaba error para usuario no verificado, obtenido user: %+v", user)
		}
		if err.Error() != "usuario no verificado" {
			t.Errorf("error esperado 'usuario no verificado', obtenido: %v", err)
		}
	})

	t.Run("Usuario desactivado es rechazado", func(t *testing.T) {
		repo := &mockUserRepo{
			user: model.User{
				Email:      "inactive@test.com",
				IsActive:   false,
				IsVerified: true,
			},
		}
		svc := &userService{userRepo: repo}
		user, err := svc.FindVerifiedUserByID(1)
		if err == nil {
			t.Fatalf("se esperaba error para usuario desactivado, obtenido user: %+v", user)
		}
		if err.Error() != "usuario desactivado" {
			t.Errorf("error esperado 'usuario desactivado', obtenido: %v", err)
		}
	})

	t.Run("Usuario inexistente retorna error", func(t *testing.T) {
		repo := &mockUserRepo{
			err: errors.New("record not found"),
		}
		svc := &userService{userRepo: repo}
		user, err := svc.FindVerifiedUserByID(999)
		if err == nil {
			t.Fatalf("se esperaba error para usuario inexistente, obtenido user: %+v", user)
		}
		if err.Error() != "usuario no encontrado" {
			t.Errorf("error esperado 'usuario no encontrado', obtenido: %v", err)
		}
	})
}

func TestUserService_GenerateResetToken_InvalidatesPreviousTokens(t *testing.T) {
	resetRepo := newMockPasswordResetRepo()
	svc := &userService{
		passwordResetRepo: resetRepo,
	}

	userID := uint(42)
	appID := uint(1)

	// Generar primer token de reset
	token1, _, err := svc.GenerateResetToken(userID, appID)
	if err != nil {
		t.Fatalf("GenerateResetToken fallo para token1: %v", err)
	}

	// Verificar que el token1 es válido inmediatamente después de generarse
	reset1, err := resetRepo.FindValidPasswordReset(token1)
	if err != nil {
		t.Fatalf("se esperaba token1 valido, obtenido error: %v", err)
	}
	if reset1.UsedAt != nil {
		t.Fatalf("se esperaba token1 sin usar")
	}

	// Generar segundo token para el mismo usuario
	token2, _, err := svc.GenerateResetToken(userID, appID)
	if err != nil {
		t.Fatalf("GenerateResetToken fallo para token2: %v", err)
	}

	// El token1 ahora DEBE haber sido invalidado
	_, err = resetRepo.FindValidPasswordReset(token1)
	if err == nil {
		t.Fatalf("se esperaba que token1 estuviera invalidado tras generar token2")
	}

	// El token2 DEBE estar activo
	reset2, err := resetRepo.FindValidPasswordReset(token2)
	if err != nil {
		t.Fatalf("se esperaba que token2 fuera valido, obtenido error: %v", err)
	}
	if reset2.UsedAt != nil {
		t.Fatalf("se esperaba token2 activo")
	}

	// Verificar que se invocó InvalidateAllUserTokens para este usuario
	if resetRepo.invalidatedCalls[userID] < 2 {
		t.Errorf("se esperaba al menos 2 llamadas a InvalidateAllUserTokens, obtenidas: %d", resetRepo.invalidatedCalls[userID])
	}
}

func TestUserService_ResetPassword_InvalidatesAllRemainingTokens(t *testing.T) {
	resetRepo := newMockPasswordResetRepo()
	userRepo := &mockUserRepo{
		user: model.User{
			ID:         42,
			Email:      "user@test.com",
			IsActive:   true,
			IsVerified: true,
		},
	}
	refreshRepo := newMockRefreshTokenRepo()
	ruleSvc := &mockRuleServiceForReset{rules: nil}

	txRepo := &mockTxRepo{
		refreshRepo:       refreshRepo,
		passwordResetRepo: resetRepo,
		userRepo:          userRepo,
	}
	txMgr := &mockTxManager{txRepo: txRepo}

	svc := &userService{
		userRepo:          userRepo,
		passwordResetRepo: resetRepo,
		ruleService:       ruleSvc,
		txManager:         txMgr,
	}

	userID := uint(42)
	appID := uint(0)

	// Crear el token que se usará para el cambio de contraseña
	tokenUsed, _, err := svc.GenerateResetToken(userID, appID)
	if err != nil {
		t.Fatalf("Error al generar token de reset: %v", err)
	}

	// Simular un token secundario activo en BD para el mismo usuario
	dummyHash := sha256.Sum256([]byte("extra-token-plain"))
	dummyReset := &model.PasswordReset{
		UserID:        userID,
		ApplicationID: appID,
		TokenHash:     dummyHash[:],
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	if err := resetRepo.CreatePasswordReset(dummyReset); err != nil {
		t.Fatalf("Error creando dummy reset: %v", err)
	}

	// Ejecutar ResetPassword usando tokenUsed
	newPassword := "NewValidPassword123!"
	err = svc.ResetPassword(tokenUsed, newPassword)
	if err != nil {
		t.Fatalf("ResetPassword fallo: %v", err)
	}

	// Ambos tokens (el usado y el extra) deben estar invalidados
	_, err = resetRepo.FindValidPasswordReset(tokenUsed)
	if err == nil {
		t.Errorf("se esperaba que tokenUsed estuviera invalidado tras ResetPassword")
	}

	_, err = resetRepo.FindValidPasswordReset("extra-token-plain")
	if err == nil {
		t.Errorf("se esperaba que el token extra estuviera invalidado tras ResetPassword")
	}

	// Verificar que la contraseña fue actualizada
	if resetRepo.updatedPasswords[userID] == "" {
		t.Errorf("se esperaba que la contraseña haya sido actualizada en repo")
	}
}

func TestUserService_ResetPassword_PreventsTokenReuse(t *testing.T) {
	resetRepo := newMockPasswordResetRepo()
	userRepo := &mockUserRepo{
		user: model.User{
			ID:         10,
			Email:      "victim@test.com",
			IsActive:   true,
			IsVerified: true,
		},
	}
	refreshRepo := newMockRefreshTokenRepo()
	ruleSvc := &mockRuleServiceForReset{rules: nil}

	txRepo := &mockTxRepo{
		refreshRepo:       refreshRepo,
		passwordResetRepo: resetRepo,
		userRepo:          userRepo,
	}
	txMgr := &mockTxManager{txRepo: txRepo}

	svc := &userService{
		userRepo:          userRepo,
		passwordResetRepo: resetRepo,
		ruleService:       ruleSvc,
		txManager:         txMgr,
	}

	userID := uint(10)
	appID := uint(0)

	token, _, err := svc.GenerateResetToken(userID, appID)
	if err != nil {
		t.Fatalf("GenerateResetToken fallo: %v", err)
	}

	// Primer intento de reset: debe tener éxito
	err = svc.ResetPassword(token, "Password123!")
	if err != nil {
		t.Fatalf("Primer ResetPassword debio ser exitoso: %v", err)
	}

	// Segundo intento con el mismo token: debe ser rechazado rotundamente
	err = svc.ResetPassword(token, "AnotherPassword123!")
	if err == nil {
		t.Fatalf("Se esperaba error al reutilizar el token de reset, pero no fallo")
	}
}

func TestUserService_Refresh_AtomicRotationAndPreventsConcurrentReuse(t *testing.T) {
	tm := newServiceTestJWTManager(t)
	refreshRepo := newMockRefreshTokenRepo()
	userRepo := &mockUserRepo{
		user: model.User{
			ID:         1,
			Email:      "test@example.com",
			IsActive:   true,
			IsVerified: true,
		},
	}
	appRepo := newMockAppRepo()
	appRepo.apps["client-app-1"] = &model.Application{
		Model:    gorm.Model{ID: 1},
		AppID:    "client-app-1",
		IsActive: true,
	}
	uarRepo := &mockUARRepo{
		roles: map[uint][]string{1: {"USER"}},
	}
	ruleSvc := &mockRuleServiceForReset{rules: nil}
	txRepo := &mockTxRepo{
		refreshRepo: refreshRepo,
		userRepo:    userRepo,
	}
	txMgr := &mockTxManager{txRepo: txRepo}

	svc := &userService{
		userRepo:         userRepo,
		appRepo:          appRepo,
		uarRepo:          uarRepo,
		refreshTokenRepo: refreshRepo,
		ruleService:      ruleSvc,
		tokenManager:     tm,
		txManager:        txMgr,
	}

	rawToken := "sample_refresh_token_to_rotate_123"
	hash := sha256.Sum256([]byte(rawToken))
	tokenHashStr := hex.EncodeToString(hash[:])

	rt := &model.RefreshToken{
		UserID:        1,
		ApplicationID: 1,
		Token:         tokenHashStr,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	if err := refreshRepo.Create(rt); err != nil {
		t.Fatalf("error creando refresh token: %v", err)
	}

	// Primer intento de refresh: debe tener éxito y rotar el token
	resp, err := svc.Refresh(rawToken)
	if err != nil {
		t.Fatalf("primer Refresh debió tener éxito: %v", err)
	}
	if resp.RefreshToken == "" || resp.AccessToken == "" {
		t.Fatalf("se esperaban tokens no vacíos en la respuesta")
	}

	// Segundo intento con el MISMO refresh token (intento de reutilización concurrente):
	// Debe ser rechazado porque el token viejo ya fue consumido atómicamente
	_, err = svc.Refresh(rawToken)
	if err == nil {
		t.Fatalf("se esperaba que el segundo Refresh fallara al intentar reutilizar el refresh token")
	}
}


func TestVerifyEmail_AtomicClaimAndReplayPrevention(t *testing.T) {
	rawToken := "email_verify_secret_token_123"
	expectedHash := sha256.Sum256([]byte(rawToken))

	var consumed bool
	userRepo := &mockUserRepo{
		verifyEmailByTokenFn: func(tokenHash []byte) (uint, uint, error) {
			if !bytes.Equal(tokenHash, expectedHash[:]) {
				return 0, 0, fmt.Errorf("hash no coincide")
			}
			if consumed {
				return 0, 0, gorm.ErrRecordNotFound
			}
			consumed = true
			return 42, 10, nil
		},
	}

	svc := &userService{
		userRepo: userRepo,
	}

	// 1. Primer intento de verificación exitoso
	uid, appID, err := svc.VerifyEmail(rawToken)
	if err != nil {
		t.Fatalf("se esperaba verificación exitosa, obtenido error: %v", err)
	}
	if uid != 42 || appID != 10 {
		t.Fatalf("se esperaba uid=42 y appID=10, obtenido uid=%d, appID=%d", uid, appID)
	}

	// 2. Segundo intento con el mismo token (replay) debe fallar
	_, _, err = svc.VerifyEmail(rawToken)
	if err == nil || !strings.Contains(err.Error(), "token inválido o expirado") {
		t.Fatalf("se esperaba rechazo por token ya consumido/expirado, obtenido: %v", err)
	}
}

func TestSendResetEmail_AtomicEligibilityAndQuota(t *testing.T) {
	resetRepo := newMockPasswordResetRepo()
	userRepo := &mockUserRepo{}
	txRepo := &mockTxRepo{passwordResetRepo: resetRepo, userRepo: userRepo}
	txMgr := &mockTxManager{txRepo: txRepo}

	svc := &userService{
		txManager:         txMgr,
		passwordResetRepo: resetRepo,
	}

	user := &model.User{
		Model: gorm.Model{ID: 10},
		Email: "test@example.com",
	}

	// 1. Primer envío exitoso
	err := svc.SendResetEmail(user, 1)
	if err != nil {
		t.Fatalf("primer SendResetEmail debió tener éxito: %v", err)
	}
	if len(resetRepo.userTokens[10]) != 1 {
		t.Fatalf("se esperaba 1 token creado, hay: %d", len(resetRepo.userTokens[10]))
	}

	// 2. Intento inmediato dentro de los 15 minutos debe fallar por cooldown atómico
	err = svc.SendResetEmail(user, 1)
	if err == nil || !strings.Contains(err.Error(), "debe esperar al menos 15 minutos") {
		t.Fatalf("se esperaba error por cooldown de 15 minutos, obtenido: %v", err)
	}

	// 3. Simular que pasaron 20 minutos
	for _, tok := range resetRepo.userTokens[10] {
		tok.CreatedAt = time.Now().Add(-20 * time.Minute)
	}

	// Segundo envío exitoso tras pasar el cooldown
	err = svc.SendResetEmail(user, 1)
	if err != nil {
		t.Fatalf("segundo SendResetEmail debió tener éxito tras cooldown: %v", err)
	}

	// 4. Simular que pasaron otros 20 minutos y que ya se alcanzaron 5 restablecimientos este mes
	for _, tok := range resetRepo.userTokens[10] {
		tok.CreatedAt = time.Now().Add(-20 * time.Minute)
	}
	for i := 0; i < 3; i++ {
		resetRepo.userTokens[10] = append(resetRepo.userTokens[10], &model.PasswordReset{
			UserID:    10,
			CreatedAt: time.Now().Add(-time.Duration(i+1) * time.Hour),
		})
	}
	// Ahora hay >= 5 tokens
	err = svc.SendResetEmail(user, 1)
	if err == nil || !strings.Contains(err.Error(), "límite mensual alcanzado") {
		t.Fatalf("se esperaba error por cuota mensual alcanzada, obtenido: %v", err)
	}
}

