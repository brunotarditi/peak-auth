package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"peak-auth/internal/api/request"
	"peak-auth/internal/api/response"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

// --- Mocks para pruebas de Service ---

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

type mockOAuthRepo struct {
	codes map[string]*model.OAuthCode
}

func newMockOAuthRepo() *mockOAuthRepo {
	return &mockOAuthRepo{codes: make(map[string]*model.OAuthCode)}
}

func (m *mockOAuthRepo) CreateCode(code *model.OAuthCode) error {
	m.codes[code.Code] = code
	return nil
}

func (m *mockOAuthRepo) GetAndConsumeCode(codeStr string) (*model.OAuthCode, error) {
	code, exists := m.codes[codeStr]
	if !exists {
		return nil, &testError{msg: "código no encontrado"}
	}
	delete(m.codes, codeStr)
	return code, nil
}

func (m *mockOAuthRepo) DeleteExpiredCodes() error {
	return nil
}

type mockAppRepo struct {
	apps map[string]*model.Application
}

func newMockAppRepo() *mockAppRepo {
	return &mockAppRepo{apps: make(map[string]*model.Application)}
}

func (m *mockAppRepo) FindByAppID(appID string) (model.Application, error) {
	app, exists := m.apps[appID]
	if !exists {
		return model.Application{}, &testError{msg: "app no encontrada"}
	}
	return *app, nil
}

func (m *mockAppRepo) ValidateSecret(appID, secret string) (model.Application, error) {
	app, exists := m.apps[appID]
	if !exists {
		return model.Application{}, &testError{msg: "app no encontrada"}
	}
	if app.SecretKey != secret {
		return model.Application{}, &testError{msg: "secreto incorrecto"}
	}
	return *app, nil
}

func (m *mockAppRepo) Create(app *model.Application) error { return nil }
func (m *mockAppRepo) Update(app *model.Application) error { return nil }
func (m *mockAppRepo) Delete(id uint) error                { return nil }
func (m *mockAppRepo) FindByID(id uint) (model.Application, error) {
	for _, a := range m.apps {
		if a.ID == id {
			return *a, nil
		}
	}
	return model.Application{}, &testError{msg: "app no encontrada"}
}
func (m *mockAppRepo) FindByName(name string) (model.Application, error)                  { return model.Application{}, nil }
func (m *mockAppRepo) GetAppsWithUserCount() ([]response.AppStatsResponse, error)         { return nil, nil }
func (m *mockAppRepo) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error)  { return nil, nil }

type mockUserRepo struct {
	user model.User
	err  error
}

func (m *mockUserRepo) FindAll() ([]model.User, error)                                   { return nil, nil }
func (m *mockUserRepo) CreateWithProfile(user *model.User, profile *model.Profile) error { return nil }
func (m *mockUserRepo) VerifyUserEmail(userID uint, verificationID uint) error          { return nil }
func (m *mockUserRepo) FindByEmail(email string) (model.User, error) {
	if m.err != nil {
		return model.User{}, m.err
	}
	return m.user, nil
}
func (m *mockUserRepo) FindById(ID uint) (model.User, error)                             { return m.user, nil }
func (m *mockUserRepo) UpdateColumn(column string, value interface{}, id uint) error    { return nil }

type mockUARRepo struct {
	roles map[uint][]string
}

func (m *mockUARRepo) AssignRole(userID, appID, roleID uint) error                                    { return nil }
func (m *mockUARRepo) RevokeAccess(userID, appID uint) error                                          { return nil }
func (m *mockUARRepo) FindRolesByUserAndApp(userID, appID uint) ([]model.Role, error) {
	if roleNames, ok := m.roles[userID]; ok {
		var result []model.Role
		for _, name := range roleNames {
			result = append(result, model.Role{Name: name})
		}
		return result, nil
	}
	return nil, nil
}
func (m *mockUARRepo) GetUserRolesInApp(userID, appID uint) ([]string, error)                         { return m.roles[userID], nil }
func (m *mockUARRepo) GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error)               { return nil, nil }
func (m *mockUARRepo) GetUsersWithRolesByAppPaginated(appID uint, page, limit int) ([]response.UserAppRow, int64, error) { return nil, 0, nil }
func (m *mockUARRepo) BelongsToApp(userID, appID uint) (bool, error)                                 { return true, nil }
func (m *mockUARRepo) IsAppAdmin(userID, appID uint) (bool, error)                                   { return true, nil }
func (m *mockUARRepo) HasAdminRoleInAnyApp(userID uint) (bool, error)                                 { return true, nil }

type mockRuleRepo struct {
	rules []model.ApplicationRules
}

func (m *mockRuleRepo) GetRulesByAppID(appID uint) ([]model.ApplicationRules, error) {
	return m.rules, nil
}
func (m *mockRuleRepo) CreateDefaultRules(appID uint) error            { return nil }
func (m *mockRuleRepo) CreateRule(appID uint, code string, val []byte) error { return nil }
func (m *mockRuleRepo) UpdateRuleValue(appID uint, code string, val []byte) error { return nil }
func (m *mockRuleRepo) DeleteRule(appID uint, code string) error       { return nil }

type mockRefreshTokenRepo struct {
	tokens              map[string]*model.RefreshToken
	deletedByUserAndApp bool
}

func newMockRefreshTokenRepo() *mockRefreshTokenRepo {
	return &mockRefreshTokenRepo{tokens: make(map[string]*model.RefreshToken)}
}

func (m *mockRefreshTokenRepo) Create(token *model.RefreshToken) error {
	if m.tokens == nil {
		m.tokens = make(map[string]*model.RefreshToken)
	}
	m.tokens[token.Token] = token
	return nil
}

func (m *mockRefreshTokenRepo) FindByToken(token string) (model.RefreshToken, error) {
	if m.tokens != nil {
		if t, ok := m.tokens[token]; ok {
			return *t, nil
		}
	}
	return model.RefreshToken{}, gorm.ErrRecordNotFound
}

func (m *mockRefreshTokenRepo) DeleteByToken(token string) error {
	if m.tokens != nil {
		delete(m.tokens, token)
	}
	return nil
}

func (m *mockRefreshTokenRepo) DeleteByUser(userID uint) error { return nil }
func (m *mockRefreshTokenRepo) DeleteByUserAndApp(userID, appID uint) error {
	m.deletedByUserAndApp = true
	return nil
}

type mockTxRepo struct {
	repo.TxRepository
	refreshRepo repo.RefreshTokenRepository
}

func (m *mockTxRepo) RefreshTokens() repo.RefreshTokenRepository {
	return m.refreshRepo
}

type mockTxManager struct {
	txRepo repo.TxRepository
}

func (m *mockTxManager) WithinTransaction(fn func(tx repo.TxRepository) error) error {
	return fn(m.txRepo)
}

type mockRuleServiceForRegister struct {
	ApplicationRuleService
	policy *util.RegistrationPolicy
}

func (m *mockRuleServiceForRegister) ValidateRegistration(appID uint, req request.RegisterRequest) (*util.RegistrationPolicy, error) {
	return m.policy, nil
}

// --- Tests OAuth ---

func TestOAuthPKCEAndRedirectValidation(t *testing.T) {
	oauthRepo := newMockOAuthRepo()
	appRepo := newMockAppRepo()

	clientID := "test-client-app"
	clientSecret := "secret123"
	redirectURI := "https://myapp.com/callback"

	appRepo.apps[clientID] = &model.Application{
		AppID:       clientID,
		SecretKey:   clientSecret,
		RedirectURL: redirectURI,
		IsActive:    true,
	}

	oauthSvc := &oauthService{
		oauthRepo: oauthRepo,
		appRepo:   appRepo,
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code, err := oauthSvc.GenerateAuthorizationCode(42, clientID, redirectURI, challenge, "S256")
	if err != nil {
		t.Fatalf("error generando authorization code: %v", err)
	}

	savedCode := *oauthRepo.codes[code]
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "https://evil.com/callback", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por redirect_uri incorrecta")
	}

	oauthRepo.codes[code] = &savedCode
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por omitir redirect_uri")
	}

	oauthRepo.codes[code] = &savedCode
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, "wrong-verifier-12345678901234567890")
	if err == nil {
		t.Fatalf("se esperaba error por code_verifier incorrecto")
	}

	oauthRepo.codes[code] = &savedCode
	userID, err := oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err != nil {
		t.Fatalf("error inesperado en canje válido: %v", err)
	}
	if userID != 42 {
		t.Fatalf("se esperaba userID 42, obtenido: %d", userID)
	}

	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err == nil {
		t.Fatalf("se esperaba error al intentar reutilizar código ya consumido")
	}
}

// --- Tests MFA ---

func TestRecoveryCodeHashingAndVerification(t *testing.T) {
	code := "ABCD-1234"

	hash := hashRecoveryCode(code)
	if len(hash) <= 7 || hash[:7] != "sha256:" {
		t.Fatalf("se esperaba prefijo sha256:, obtenido: %s", hash)
	}

	testCases := []string{
		"ABCD-1234",
		"abcd-1234",
		"ABCD1234",
		"abcd1234",
		"  ABCD-1234  ",
	}
	for _, tc := range testCases {
		if !verifyRecoveryCodeHash(tc, hash) {
			t.Errorf("falló verificación de código válido con formato: %s", tc)
		}
	}

	if verifyRecoveryCodeHash("WXYZ-9999", hash) {
		t.Errorf("código incorrecto fue aceptado")
	}
	if verifyRecoveryCodeHash("", hash) {
		t.Errorf("código vacío fue aceptado")
	}
}

// --- Tests User Service ---

func TestAdminLogin_RejectsDeactivatedUser(t *testing.T) {
	userRepo := &mockUserRepo{
		user: model.User{
			Email:      "admin@peak.test",
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

	_, _, _, _, _, err := svc.AdminLogin("admin@peak.test", "")
	if err == nil || err.Error() != "usuario desactivado" {
		t.Fatalf("Esperaba error 'usuario desactivado', pero obtuvo: %v", err)
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

	_, err := svc.CompleteLoginWithMfa(1, "my-app")
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

func TestRegister_ForbidsAdminAndRootRole(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app"}

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

// --- Tests Application Rule Service ---

func TestValidateRegistration_ForbidsAdminRole(t *testing.T) {
	ruleRepo := &mockRuleRepo{
		rules: []model.ApplicationRules{
			{
				Code:  "REGISTRATION_POLICY",
				Value: []byte("{\"mode\":\"public\",\"default_role\":\"ADMIN\"}"),
			},
		},
	}
	appRepo := newMockAppRepo()
	ruleSvc := NewApplicationRuleService(ruleRepo, nil, nil, appRepo)

	_, err := ruleSvc.ValidateRegistration(1, request.RegisterRequest{})
	if err == nil {
		t.Fatalf("Esperaba que ValidateRegistration rechazara default_role ADMIN en registro público")
	}
}

func TestValidateRegistration_ForbidsRootRole(t *testing.T) {
	ruleRepo := &mockRuleRepo{
		rules: []model.ApplicationRules{
			{
				Code:  "REGISTRATION_POLICY",
				Value: []byte("{\"mode\":\"public\",\"default_role\":\"ROOT\"}"),
			},
		},
	}
	appRepo := newMockAppRepo()
	ruleSvc := NewApplicationRuleService(ruleRepo, nil, nil, appRepo)

	_, err := ruleSvc.ValidateRegistration(1, request.RegisterRequest{})
	if err == nil {
		t.Fatalf("Esperaba que ValidateRegistration rechazara default_role ROOT en registro público")
	}
}

func TestCreateRule_ForbidsAdminRoleInPublicMode(t *testing.T) {
	ruleRepo := &mockRuleRepo{}
	appRepo := newMockAppRepo()
	ruleSvc := NewApplicationRuleService(ruleRepo, nil, nil, appRepo)

	err := ruleSvc.CreateRule(1, "REGISTRATION_POLICY", []byte("{\"mode\":\"public\",\"default_role\":\"ADMIN\"}"))
	if err == nil {
		t.Fatalf("Esperaba que CreateRule rechazara default_role ADMIN en registro público")
	}
}

// --- Tests Application Service ---

func TestRevokeUserFromApp_DeletesRefreshTokens(t *testing.T) {
	refreshRepo := &mockRefreshTokenRepo{}
	uarRepo := &mockUARRepo{
		roles: map[uint][]string{1: {"USER"}},
	}
	appRepo := newMockAppRepo()
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app"}

	appSvc := &applicationService{
		repo:             appRepo,
		uarRepo:          uarRepo,
		refreshTokenRepo: refreshRepo,
	}

	err := appSvc.RevokeUserFromApp(1, 10)
	if err != nil {
		t.Fatalf("error inesperado en RevokeUserFromApp: %v", err)
	}
	if !refreshRepo.deletedByUserAndApp {
		t.Fatalf("RevokeUserFromApp no eliminó los refresh tokens de la aplicación")
	}
}

func TestRevokeUserFromApp_ProtectsRootUserInPeakAuth(t *testing.T) {
	refreshRepo := &mockRefreshTokenRepo{}
	uarRepo := &mockUARRepo{
		roles: map[uint][]string{1: {"ROOT"}},
	}
	appRepo := newMockAppRepo()
	peakApp := &model.Application{AppID: util.AppIdPeakAuth}
	peakApp.ID = 1
	appRepo.apps[util.AppIdPeakAuth] = peakApp

	appSvc := &applicationService{
		repo:             appRepo,
		uarRepo:          uarRepo,
		refreshTokenRepo: refreshRepo,
	}

	err := appSvc.RevokeUserFromApp(1, 1)
	if err == nil {
		t.Fatalf("Esperaba error al intentar revocar al usuario ROOT en la app raíz")
	}
	if refreshRepo.deletedByUserAndApp {
		t.Fatalf("Los tokens no debieron eliminarse porque la operación debía fallar")
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

