package service

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
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
	codes    map[string]*model.OAuthCode
	consents map[string]bool // key: "userID:clientID"
}

func newMockOAuthRepo() *mockOAuthRepo {
	return &mockOAuthRepo{
		codes:    make(map[string]*model.OAuthCode),
		consents: make(map[string]bool),
	}
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

func (m *mockOAuthRepo) HasValidConsent(userID uint, clientID string) (bool, error) {
	key := fmt.Sprintf("%d:%s", userID, clientID)
	return m.consents[key], nil
}

func (m *mockOAuthRepo) CreateConsent(consent *model.UserConsent) error {
	key := fmt.Sprintf("%d:%s", consent.UserID, consent.ClientID)
	m.consents[key] = true
	return nil
}

func (m *mockOAuthRepo) RevokeConsent(userID uint, clientID string) error {
	key := fmt.Sprintf("%d:%s", userID, clientID)
	delete(m.consents, key)
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
func (m *mockAppRepo) UpdateColumns(id uint, columns map[string]interface{}) error {
	for _, a := range m.apps {
		if a.ID == id {
			if desc, ok := columns["description"].(string); ok {
				a.Description = desc
			}
			if red, ok := columns["redirect_url"].(string); ok {
				a.RedirectURL = red
			}
			if act, ok := columns["is_active"].(bool); ok {
				a.IsActive = act
			}
			if sec, ok := columns["secret_key"].(string); ok {
				a.SecretKey = sec
			}
			return nil
		}
	}
	return nil
}
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
	user                 model.User
	err                  error
	verifyEmailByTokenFn func(tokenHash []byte) (uint, uint, error)
}

func (m *mockUserRepo) FindAll() ([]model.User, error)                                   { return nil, nil }
func (m *mockUserRepo) CreateWithProfile(user *model.User, profile *model.Profile) error { return nil }
func (m *mockUserRepo) VerifyUserEmail(userID uint, verificationID uint) error          { return nil }
func (m *mockUserRepo) VerifyUserEmailByToken(tokenHash []byte) (uint, uint, error) {
	if m.verifyEmailByTokenFn != nil {
		return m.verifyEmailByTokenFn(tokenHash)
	}
	return 0, 0, nil
}
func (m *mockUserRepo) FindByEmail(email string) (model.User, error) {
	if m.err != nil {
		return model.User{}, m.err
	}
	return m.user, nil
}
func (m *mockUserRepo) FindById(ID uint) (model.User, error) {
	if m.err != nil {
		return model.User{}, m.err
	}
	return m.user, nil
}
func (m *mockUserRepo) UpdateColumn(column string, value interface{}, id uint) error    { return nil }

type mockUARRepo struct {
	roles                map[uint][]string
	hasAdminRoleInAnyApp *bool
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
func (m *mockUARRepo) HasAdminRoleInAnyApp(userID uint) (bool, error) {
	if m.hasAdminRoleInAnyApp != nil {
		return *m.hasAdminRoleInAnyApp, nil
	}
	return true, nil
}

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

func (m *mockRefreshTokenRepo) DeleteByTokenAtomic(token string) (int64, error) {
	if m.tokens != nil {
		if _, ok := m.tokens[token]; ok {
			delete(m.tokens, token)
			return 1, nil
		}
	}
	return 0, nil
}

func (m *mockRefreshTokenRepo) DeleteByUser(userID uint) error { return nil }
func (m *mockRefreshTokenRepo) DeleteByUserAndApp(userID, appID uint) error {
	m.deletedByUserAndApp = true
	return nil
}
func (m *mockRefreshTokenRepo) DeleteByApp(appID uint) error { return nil }

type mockPasswordResetRepo struct {
	tokens           map[string]*model.PasswordReset
	userTokens       map[uint][]*model.PasswordReset
	invalidatedCalls map[uint]int
	updatedPasswords map[uint]string
	nextID           uint
}

func newMockPasswordResetRepo() *mockPasswordResetRepo {
	return &mockPasswordResetRepo{
		tokens:           make(map[string]*model.PasswordReset),
		userTokens:       make(map[uint][]*model.PasswordReset),
		invalidatedCalls: make(map[uint]int),
		updatedPasswords: make(map[uint]string),
	}
}

func (m *mockPasswordResetRepo) CheckLastTimeTokenReset(userId uint) (time.Time, error) {
	var latest time.Time
	for _, tok := range m.userTokens[userId] {
		if tok.UsedAt == nil && (tok.ExpiresAt.IsZero() || tok.ExpiresAt.After(time.Now())) {
			if tok.CreatedAt.After(latest) {
				latest = tok.CreatedAt
			}
		}
	}
	if latest.IsZero() {
		return time.Time{}, gorm.ErrRecordNotFound
	}
	return latest, nil
}

func (m *mockPasswordResetRepo) FindValidPasswordReset(plainToken string) (*model.PasswordReset, error) {
	hashed := sha256.Sum256([]byte(plainToken))
	key := hex.EncodeToString(hashed[:])
	r, exists := m.tokens[key]
	if !exists {
		return nil, errors.New("token no encontrado")
	}
	if r.UsedAt != nil || r.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token ya usado o expirado")
	}
	return r, nil
}

func (m *mockPasswordResetRepo) UpdatePassword(userID uint, hashed string) error {
	m.updatedPasswords[userID] = hashed
	return nil
}

func (m *mockPasswordResetRepo) MarkPasswordResetUsed(resetID uint, usedAt time.Time) error {
	for _, r := range m.tokens {
		if r.ID == resetID {
			if r.UsedAt != nil {
				return gorm.ErrRecordNotFound
			}
			r.UsedAt = &usedAt
			return nil
		}
	}
	return errors.New("token no encontrado")
}

func (m *mockPasswordResetRepo) CreatePasswordReset(reset *model.PasswordReset) error {
	m.nextID++
	reset.ID = m.nextID
	if reset.CreatedAt.IsZero() {
		reset.CreatedAt = time.Now()
	}
	m.userTokens[reset.UserID] = append(m.userTokens[reset.UserID], reset)
	if len(reset.TokenHash) > 0 {
		key := hex.EncodeToString(reset.TokenHash)
		m.tokens[key] = reset
	}
	return nil
}

func (m *mockPasswordResetRepo) CountResetsThisMonth(userID uint) (int64, error) {
	return int64(len(m.userTokens[userID])), nil
}

func (m *mockPasswordResetRepo) InvalidateAllUserTokens(userID uint) error {
	m.invalidatedCalls[userID]++
	for _, r := range m.userTokens[userID] {
		if r.UsedAt == nil && r.ExpiresAt.After(time.Now()) {
			now := time.Now()
			r.UsedAt = &now
		}
	}
	return nil
}

type mockTxRepo struct {
	repo.TxRepository
	refreshRepo       repo.RefreshTokenRepository
	passwordResetRepo repo.PasswordResetRepository
	userRepo          repo.UserRepository
}

func (m *mockTxRepo) RefreshTokens() repo.RefreshTokenRepository {
	return m.refreshRepo
}

func (m *mockTxRepo) PasswordResets() repo.PasswordResetRepository {
	return m.passwordResetRepo
}

func (m *mockTxRepo) Users() repo.UserRepository {
	return m.userRepo
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

type mockRuleServiceForReset struct {
	ApplicationRuleService
	rules []model.ApplicationRules
}

func (m *mockRuleServiceForReset) FindRulesByAppID(appID uint) ([]model.ApplicationRules, error) {
	return m.rules, nil
}

func (m *mockRuleServiceForReset) ValidateLogin(appID, userID uint) error {
	return nil
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

	code, err := oauthSvc.GenerateAuthorizationCode(42, clientID, redirectURI, challenge, "S256", true)
	if err != nil {
		t.Fatalf("error generando authorization code: %v", err)
	}

	savedCode := *oauthRepo.codes[code]
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "https://evil.com/callback", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por redirect_uri incorrecta")
	}

	oauthRepo.codes[code] = &savedCode
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por omitir redirect_uri")
	}

	oauthRepo.codes[code] = &savedCode
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, "wrong-verifier-12345678901234567890")
	if err == nil {
		t.Fatalf("se esperaba error por code_verifier incorrecto")
	}

	oauthRepo.codes[code] = &savedCode
	userID, mfaCompleted, err := oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err != nil {
		t.Fatalf("error inesperado en canje válido: %v", err)
	}
	if userID != 42 {
		t.Fatalf("se esperaba userID 42, obtenido: %d", userID)
	}
	if !mfaCompleted {
		t.Fatalf("se esperaba mfaCompleted true, obtenido: %v", mfaCompleted)
	}

	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err == nil {
		t.Fatalf("se esperaba error al intentar reutilizar código ya consumido")
	}

	t.Run("Cliente público con PKCE puede canjear sin client_secret", func(t *testing.T) {
		publicCode, err := oauthSvc.GenerateAuthorizationCode(99, clientID, redirectURI, challenge, "S256", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		uID, mfa, err := oauthSvc.ExchangeCodeForToken(clientID, "", publicCode, redirectURI, verifier)
		if err != nil {
			t.Fatalf("cliente público con PKCE debería poder canjear sin client_secret, error: %v", err)
		}
		if uID != 99 {
			t.Fatalf("se esperaba userID 99, obtenido %d", uID)
		}
		if mfa {
			t.Fatalf("se esperaba mfa false, obtenido %v", mfa)
		}
	})

	t.Run("Cliente sin client_secret y sin PKCE es rechazado", func(t *testing.T) {
		noPkceCode, err := oauthSvc.GenerateAuthorizationCode(99, clientID, redirectURI, "", "", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		_, _, err = oauthSvc.ExchangeCodeForToken(clientID, "", noPkceCode, redirectURI, "")
		if err == nil {
			t.Fatalf("se esperaba rechazo al intentar canjear código sin PKCE y sin client_secret")
		}
	})

	t.Run("Cliente público con app desactivada es rechazado", func(t *testing.T) {
		inactiveClientID := "inactive-client"
		appRepo.apps[inactiveClientID] = &model.Application{
			AppID:       inactiveClientID,
			RedirectURL: redirectURI,
			IsActive:    true,
		}

		inactiveCode, err := oauthSvc.GenerateAuthorizationCode(99, inactiveClientID, redirectURI, challenge, "S256", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		// La aplicación se desactiva antes del canje
		appRepo.apps[inactiveClientID].IsActive = false

		_, _, err = oauthSvc.ExchangeCodeForToken(inactiveClientID, "", inactiveCode, redirectURI, verifier)
		if err == nil {
			t.Fatalf("se esperaba rechazo para aplicación desactivada")
		}
	})
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

type mockRuleServiceForMfa struct {
	ApplicationRuleService
	rules []model.ApplicationRules
}

func (m *mockRuleServiceForMfa) ValidateLogin(appID, userID uint) error {
	return nil
}

func (m *mockRuleServiceForMfa) FindRulesByAppID(appID uint) ([]model.ApplicationRules, error) {
	return m.rules, nil
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

func TestSessionPolicy_MutationAndResolutionBoundsValidation(t *testing.T) {
	ruleRepo := &mockRuleRepo{}
	appRepo := newMockAppRepo()
	ruleSvc := NewApplicationRuleService(ruleRepo, nil, nil, appRepo)

	tests := []struct {
		name        string
		val         string
		wantErr     bool
		errContains string
	}{
		{
			name:    "duración mínima válida (5 minutos)",
			val:     `{"token_expiration_minutes": 5}`,
			wantErr: false,
		},
		{
			name:    "duración estándar válida (15 minutos)",
			val:     `{"token_expiration_minutes": 15}`,
			wantErr: false,
		},
		{
			name:    "duración máxima válida (10080 minutos / 7 días)",
			val:     `{"token_expiration_minutes": 10080}`,
			wantErr: false,
		},
		{
			name:        "duración menor al mínimo (4 minutos)",
			val:         `{"token_expiration_minutes": 4}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración cero",
			val:         `{"token_expiration_minutes": 0}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración negativa",
			val:         `{"token_expiration_minutes": -5}`,
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name:        "duración excede el máximo (10081 minutos)",
			val:         `{"token_expiration_minutes": 10081}`,
			wantErr:     true,
			errContains: "excede el máximo permitido",
		},
		{
			name:        "JSON malformado",
			val:         `{token_expiration_minutes: 60`,
			wantErr:     true,
			errContains: "política de sesión inválida",
		},
	}

	for _, tc := range tests {
		t.Run("CreateRule_"+tc.name, func(t *testing.T) {
			err := ruleSvc.CreateRule(1, "SESSION_POLICY", []byte(tc.val))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("se esperaba error conteniendo %q, obtenido: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("no se esperaba error, obtenido: %v", err)
				}
			}
		})

		t.Run("UpdateRuleValue_"+tc.name, func(t *testing.T) {
			err := ruleSvc.UpdateRuleValue(1, "SESSION_POLICY", []byte(tc.val))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("se esperaba error conteniendo %q, obtenido: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("no se esperaba error, obtenido: %v", err)
				}
			}
		})
	}
}

func TestResolveTokenDuration_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		rules        []model.ApplicationRules
		wantDuration time.Duration
		wantErr      bool
		errContains  string
	}{
		{
			name:         "sin regla SESSION_POLICY usa valor por defecto conservador (15 min)",
			rules:        []model.ApplicationRules{},
			wantDuration: 15 * time.Minute,
			wantErr:      false,
		},
		{
			name: "duración mínima válida (5 min)",
			rules: []model.ApplicationRules{
				{Code: "SESSION_POLICY", Value: []byte(`{"token_expiration_minutes": 5}`)},
			},
			wantDuration: 5 * time.Minute,
			wantErr:      false,
		},
		{
			name: "duración máxima válida (10080 min)",
			rules: []model.ApplicationRules{
				{Code: "SESSION_POLICY", Value: []byte(`{"token_expiration_minutes": 10080}`)},
			},
			wantDuration: 10080 * time.Minute,
			wantErr:      false,
		},
		{
			name: "duración por debajo de 5 min retorna error fail-closed",
			rules: []model.ApplicationRules{
				{Code: "SESSION_POLICY", Value: []byte(`{"token_expiration_minutes": 4}`)},
			},
			wantErr:     true,
			errContains: "menor al mínimo permitido",
		},
		{
			name: "duración por encima de 10080 min retorna error fail-closed",
			rules: []model.ApplicationRules{
				{Code: "SESSION_POLICY", Value: []byte(`{"token_expiration_minutes": 10081}`)},
			},
			wantErr:     true,
			errContains: "excede el máximo permitido",
		},
		{
			name: "JSON corrupto retorna error fail-closed",
			rules: []model.ApplicationRules{
				{Code: "SESSION_POLICY", Value: []byte(`{invalid json}`)},
			},
			wantErr:     true,
			errContains: "no se pudo interpretar la política de sesión",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &userService{
				ruleService: &mockRuleServiceForMfa{rules: tc.rules},
			}
			dur, err := svc.resolveTokenDuration(1)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("se esperaba error conteniendo %q, obtenido: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("no se esperaba error, obtenido: %v", err)
				}
				if dur != tc.wantDuration {
					t.Fatalf("duración obtenida %v, esperada %v", dur, tc.wantDuration)
				}
			}
		})
	}
}

func TestLogin_FailsClosedOnMalformedMfaPolicy(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["test-app"] = &model.Application{
		Model:    gorm.Model{ID: 1},
		AppID:    "test-app",
		IsActive: true,
	}

	hash, _ := util.HashPassword("ValidPassword123!")
	userRepo := &mockUserRepo{
		user: model.User{
			Model:      gorm.Model{ID: 1},
			Email:      "user@test.com",
			Password:   hash,
			IsActive:   true,
			IsVerified: true,
		},
	}

	svc := &userService{
		userRepo: userRepo,
		appRepo:  appRepo,
		uarRepo:  &mockUARRepo{roles: map[uint][]string{1: {"USER"}}},
		ruleService: &mockRuleServiceForMfa{
			rules: []model.ApplicationRules{
				{Code: "MFA_POLICY", Value: []byte(`{malformed mfa policy`)},
			},
		},
	}

	_, err := svc.Login(request.LoginRequest{
		Email:    "user@test.com",
		Password: "ValidPassword123!",
	}, "test-app")

	if err == nil || !strings.Contains(err.Error(), "no se pudo interpretar la política de MFA") {
		t.Fatalf("se esperaba fallo fail-closed por política de MFA corrupta, obtenido: %v", err)
	}
}

func TestAdminLogin_FailsClosedOnMalformedMfaPolicy(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps[util.AppIdPeakAuth] = &model.Application{
		Model:    gorm.Model{ID: 1},
		AppID:    util.AppIdPeakAuth,
		IsActive: true,
	}

	hash, _ := util.HashPassword("AdminPass123!")
	userRepo := &mockUserRepo{
		user: model.User{
			Model:      gorm.Model{ID: 1},
			Email:      "admin@peakauth.com",
			Password:   hash,
			IsActive:   true,
			IsVerified: true,
		},
	}

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{
			1: {"ROOT"},
		},
	}

	svc := &userService{
		userRepo: userRepo,
		appRepo:  appRepo,
		uarRepo:  uarRepo,
		ruleService: &mockRuleServiceForMfa{
			rules: []model.ApplicationRules{
				{Code: "MFA_POLICY", Value: []byte(`{malformed json`)},
			},
		},
	}

	_, _, _, _, _, err := svc.AdminLogin("admin@peakauth.com", "AdminPass123!")
	if err == nil || !strings.Contains(err.Error(), "no se pudo interpretar la política de MFA") {
		t.Fatalf("se esperaba fallo fail-closed por política de MFA corrupta en AdminLogin, obtenido: %v", err)
	}
}


func TestValidateRegistration_EnforcesBaselinePasswordWhenNoPwdPolicy(t *testing.T) {
	ruleRepo := &mockRuleRepo{
		rules: []model.ApplicationRules{
			{
				Code:  "REGISTRATION_POLICY",
				Value: []byte(`{"mode":"public","default_role":"USER"}`),
			},
		},
	}
	appRepo := newMockAppRepo()
	ruleSvc := NewApplicationRuleService(ruleRepo, nil, nil, appRepo)

	// Password con menos de 8 caracteres debe ser rechazada
	_, err := ruleSvc.ValidateRegistration(1, request.RegisterRequest{Password: "short"})
	if err == nil || !strings.Contains(err.Error(), "al menos 8 caracteres") {
		t.Fatalf("se esperaba rechazo por contraseña corta (<8), obtenido: %v", err)
	}

	// Password válida con complejidad debe ser aceptada
	policy, err := ruleSvc.ValidateRegistration(1, request.RegisterRequest{Password: "ValidPass123!"})
	if err != nil {
		t.Fatalf("se esperaba éxito para contraseña válida con requisitos base, obtenido: %v", err)
	}
	if policy.DefaultRole != "USER" {
		t.Fatalf("se esperaba default_role USER, obtenido: %s", policy.DefaultRole)
	}
}

func TestResetPassword_EnforcesBaselinePasswordWhenNoPwdPolicy(t *testing.T) {
	userRepo := &mockUserRepo{
		user: model.User{Model: gorm.Model{ID: 1}, Email: "user@test.com", IsActive: true, IsVerified: true},
	}
	tokenPlain := "plain_reset_token_1234567890123456"
	h := sha256.Sum256([]byte(tokenPlain))
	tokenHash := h[:]

	pwdResetRepo := newMockPasswordResetRepo()
	pwdResetRepo.tokens[hex.EncodeToString(tokenHash)] = &model.PasswordReset{
		Model:         gorm.Model{ID: 10},
		UserID:        1,
		ApplicationID: 1,
		TokenHash:     tokenHash,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	refreshRepo := newMockRefreshTokenRepo()
	txRepo := &mockTxRepo{
		refreshRepo:       refreshRepo,
		passwordResetRepo: pwdResetRepo,
		userRepo:          userRepo,
	}
	txMgr := &mockTxManager{txRepo: txRepo}

	// App sin PWD_POLICY configurada (solo devuelve lista vacía)
	ruleSvc := &mockRuleServiceForReset{
		rules: []model.ApplicationRules{},
	}

	userSvc := &userService{
		userRepo:          userRepo,
		passwordResetRepo: pwdResetRepo,
		refreshTokenRepo:  refreshRepo,
		ruleService:       ruleSvc,
		txManager:         txMgr,
	}

	// 1. Password corta (<8 chars) debe ser rechazada
	err := userSvc.ResetPassword(tokenPlain, "short")
	if err == nil || !strings.Contains(err.Error(), "al menos 8 caracteres") {
		t.Fatalf("se esperaba error de contraseña mínima de 8 caracteres, obtenido: %v", err)
	}

	// 2. Password válida con complejidad debe ser aceptada
	err = userSvc.ResetPassword(tokenPlain, "ValidPass123!")
	if err != nil {
		t.Fatalf("se esperaba éxito al resetear contraseña con requisitos base, obtenido: %v", err)
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

func TestOAuth_ValidateRedirectURISecurity(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"HTTPS standard", "https://example.com/callback", false},
		{"HTTPS with port and path", "https://portal.mycompany.com:8443/oauth/callback", false},
		{"HTTP localhost", "http://localhost:3000/callback", false},
		{"HTTP localhost with sub-domain", "http://app.localhost:8080/cb", false},
		{"HTTP 127.0.0.1", "http://127.0.0.1:8080/callback", false},
		{"HTTP 127.0.0.2", "http://127.0.0.2:8080/callback", false},
		{"HTTP IPv6 loopback", "http://[::1]:8080/callback", false},
		{"Custom mobile scheme RFC 8252 (myapp)", "myapp://oauth-callback", false},
		{"Custom mobile scheme RFC 8252 (reverse DNS)", "com.example.app:/oauth2redirect", false},
		{"HTTP external domain (insecure)", "http://example.com/callback", true},
		{"HTTP private LAN IP (insecure)", "http://192.168.1.100:3000/callback", true},
		{"HTTP 10.x LAN IP (insecure)", "http://10.0.0.1:3000/callback", true},
		{"Javascript scheme (dangerous)", "javascript:alert(1)", true},
		{"Data scheme (dangerous)", "data:text/html,test", true},
		{"File scheme (dangerous)", "file:///etc/passwd", true},
		{"URI with fragment RFC 6749 violation", "https://example.com/callback#token=abc", true},
		{"Empty string", "", true},
		{"Relative path without scheme", "/callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURISecurity(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURISecurity(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestOAuth_ValidateClientRedirect_Security(t *testing.T) {
	mockRepo := newMockOAuthRepo()
	mockApp := &mockAppRepo{
		apps: map[string]*model.Application{
			"valid-web": {
				AppID:       "valid-web",
				RedirectURL: "https://web.example.com/callback",
				IsActive:    true,
			},
			"valid-mobile": {
				AppID:       "valid-mobile",
				RedirectURL: "myapp://oauth/callback",
				IsActive:    true,
			},
			"insecure-app": {
				AppID:       "insecure-app",
				RedirectURL: "http://insecure.com/callback",
				IsActive:    true,
			},
		},
	}

	svc := NewOAuthService(mockRepo, mockApp)

	// Valid HTTPS redirect
	if err := svc.ValidateClientRedirect("valid-web", "https://web.example.com/callback"); err != nil {
		t.Fatalf("se esperaba éxito para URI HTTPS válida, error: %v", err)
	}

	// Valid mobile scheme redirect
	if err := svc.ValidateClientRedirect("valid-mobile", "myapp://oauth/callback"); err != nil {
		t.Fatalf("se esperaba éxito para URI de app móvil (RFC 8252), error: %v", err)
	}

	// Insecure HTTP to external host must be rejected even if matching registered app
	if err := svc.ValidateClientRedirect("insecure-app", "http://insecure.com/callback"); err == nil {
		t.Fatalf("se esperaba rechazo para URI HTTP no local")
	}

	// Mismatch redirect URI
	if err := svc.ValidateClientRedirect("valid-web", "https://web.example.com/other"); err == nil {
		t.Fatalf("se esperaba error por discordancia de redirect_uri")
	}
}

type mockSetupRepo struct {
	firstRun bool
	err      error
}

func (m *mockSetupRepo) IsFirstRun() (bool, error) {
	return m.firstRun, m.err
}

func TestSetupService_EphemeralToken(t *testing.T) {
	repo := &mockSetupRepo{firstRun: true}
	svc := NewSetupService(repo, "", nil)

	// Antes de InitializeSystem no hay token efímero ni configurado
	if err := svc.ValidateSetupToken("random-token"); err == nil {
		t.Fatalf("se esperaba error cuando no hay token configurado ni efímero")
	}

	// Inicializar sistema sin SETUP_TOKEN -> debe generar token efímero
	svc.InitializeSystem("8080")

	if !svc.RequiresToken() {
		t.Fatalf("se esperaba que RequiresToken() retornara true con token efímero activo")
	}

	concrete := svc.(*setupService)
	ephemeralToken := concrete.ephemeralToken
	if ephemeralToken == "" {
		t.Fatalf("se esperaba que ephemeralToken no estuviera vacío")
	}

	// Token erróneo debe fallar
	if err := svc.ValidateSetupToken("token-incorrecto"); err == nil {
		t.Fatalf("se esperaba error con token incorrecto")
	}

	// Token correcto debe ser válido
	if err := svc.ValidateSetupToken(ephemeralToken); err != nil {
		t.Fatalf("se esperaba validación exitosa con token efímero correcto: %v", err)
	}

	// Token expirado debe fallar
	concrete.tokenExpiry = time.Now().Add(-1 * time.Minute)
	if err := svc.ValidateSetupToken(ephemeralToken); err == nil {
		t.Fatalf("se esperaba error cuando el token efímero está expirado")
	}

	// Resetear expiry y completar setup
	concrete.tokenExpiry = time.Now().Add(1 * time.Hour)
	svc.CompleteSetup(model.User{Email: "root@peak.local"})

	if concrete.ephemeralToken != "" {
		t.Fatalf("CompleteSetup debió limpiar el token efímero")
	}
}

func TestSetupService_ConfiguredToken(t *testing.T) {
	repo := &mockSetupRepo{firstRun: true}
	configuredToken := "super-secret-setup-token-42"
	svc := NewSetupService(repo, configuredToken, nil)

	if !svc.RequiresToken() {
		t.Fatalf("se esperaba RequiresToken() == true con SETUP_TOKEN configurado")
	}

	if err := svc.ValidateSetupToken("wrong-token"); err == nil {
		t.Fatalf("se esperaba error con token no coincidente")
	}

	if err := svc.ValidateSetupToken(configuredToken); err != nil {
		t.Fatalf("se esperaba éxito con token coincidente: %v", err)
	}
}

func TestApplicationService_UpdateColumns_IndependentUpdates(t *testing.T) {
	initialSecret := "initial-secret-hash-123"
	app := &model.Application{
		ID:          1,
		AppID:       "test-client",
		Name:        "Test Client",
		Description: "Initial description",
		RedirectURL: "https://example.com/callback",
		SecretKey:   initialSecret,
		IsActive:    true,
	}

	appRepo := newMockAppRepo()
	appRepo.apps["test-client"] = app

	svc := NewApplicationService(appRepo, nil, nil, nil, nil, nil, nil, nil)

	// 1. UpdateApp: debe modificar metadata pero NO tocar el secret
	err := svc.UpdateApp("test-client", "Updated description", "https://example.com/new-callback", true)
	if err != nil {
		t.Fatalf("UpdateApp falló: %v", err)
	}
	if app.Description != "Updated description" {
		t.Errorf("se esperaba descripción actualizada, obtenido: %s", app.Description)
	}
	if app.RedirectURL != "https://example.com/new-callback" {
		t.Errorf("se esperaba redirect_url actualizada, obtenido: %s", app.RedirectURL)
	}
	if app.SecretKey != initialSecret {
		t.Errorf("UpdateApp no debió modificar SecretKey")
	}

	// 2. RegenerateSecret: debe modificar el secret pero NO tocar descripción ni redirect_url
	newPlainSecret, err := svc.RegenerateSecret("test-client")
	if err != nil {
		t.Fatalf("RegenerateSecret falló: %v", err)
	}
	if newPlainSecret == "" {
		t.Fatalf("se esperaba un plainSecret generado")
	}
	if app.SecretKey == initialSecret {
		t.Errorf("se esperaba que el secret cambiara")
	}
	if app.Description != "Updated description" {
		t.Errorf("RegenerateSecret no debió modificar la descripción")
	}
	if app.RedirectURL != "https://example.com/new-callback" {
		t.Errorf("RegenerateSecret no debió modificar la redirect_url")
	}
}

type mockMfaAttemptRepo struct {
	consumed map[string]bool
	locked   map[string]bool
}

func (m *mockMfaAttemptRepo) RecordFailedAttempt(challengeKey string, userID uint, maxAttempts int) (bool, error) {
	return false, nil
}
func (m *mockMfaAttemptRepo) IsLocked(challengeKey string) (bool, error) {
	return m.locked[challengeKey], nil
}
func (m *mockMfaAttemptRepo) ClearAttempts(challengeKey string) error {
	delete(m.locked, challengeKey)
	return nil
}
func (m *mockMfaAttemptRepo) CleanupExpired() error { return nil }
func (m *mockMfaAttemptRepo) MarkConsumed(challengeKey string, userID uint) error {
	if m.consumed[challengeKey] {
		return errors.New("token ya consumido")
	}
	m.consumed[challengeKey] = true
	return nil
}
func (m *mockMfaAttemptRepo) IsConsumed(challengeKey string) (bool, error) {
	return m.consumed[challengeKey], nil
}

func TestApiMfaToken_AtomicConsumptionAndReplayPrevention(t *testing.T) {
	mockRepo := &mockMfaAttemptRepo{
		consumed: make(map[string]bool),
		locked:   make(map[string]bool),
	}
	InitMfaAttemptTracking(mockRepo)

	tokenKey := "api_mfa_1_test_token"

	// 1. Antes de consumirse, IsApiMfaTokenConsumed debe ser false
	if IsApiMfaTokenConsumed(tokenKey) {
		t.Fatalf("se esperaba que el token no estuviera consumido inicialmente")
	}

	// 2. Primer consumo debe ser exitoso
	if err := ConsumeApiMfaToken(tokenKey, 1); err != nil {
		t.Fatalf("primer ConsumeApiMfaToken debió tener éxito: %v", err)
	}

	// 3. Después del consumo, IsApiMfaTokenConsumed debe ser true
	if !IsApiMfaTokenConsumed(tokenKey) {
		t.Fatalf("se esperaba que el token estuviera marcado como consumido")
	}

	// 4. Segundo intento de consumo con el mismo token (intento de replay) debe fallar
	if err := ConsumeApiMfaToken(tokenKey, 1); err == nil {
		t.Fatalf("se esperaba que el segundo intento de consumo fallara")
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
	txRepo := &mockTxRepo{passwordResetRepo: resetRepo}
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





