package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"peak-auth/internal/api/request"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"gorm.io/gorm"
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

func (m *mockOAuthRepo) GetAndConsumeCodeForClient(codeStr string, clientID string) (*model.OAuthCode, error) {
	code, exists := m.codes[codeStr]
	if !exists {
		return nil, &testError{msg: "código no encontrado"}
	}

	// Validate expiration before consuming
	if time.Now().After(code.ExpiresAt) {
		return nil, &testError{msg: "el código de autorización ha expirado"}
	}

	// Validate client binding before consuming
	if code.ClientID != clientID {
		return nil, &testError{msg: "el código no pertenece a este client_id"}
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

func (m *mockOAuthRepo) FindConsentsByUser(userID uint) ([]model.UserConsent, error) {
	var list []model.UserConsent
	for key, ok := range m.consents {
		if ok && strings.HasPrefix(key, fmt.Sprintf("%d:", userID)) {
			parts := strings.Split(key, ":")
			list = append(list, model.UserConsent{
				UserID:   userID,
				ClientID: parts[1],
			})
		}
	}
	return list, nil
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
func (m *mockAppRepo) Delete(id uint) error { return nil }
func (m *mockAppRepo) FindByID(id uint) (model.Application, error) {
	for _, a := range m.apps {
		if a.ID == id {
			return *a, nil
		}
	}
	return model.Application{}, &testError{msg: "app no encontrada"}
}
func (m *mockAppRepo) FindByName(name string) (model.Application, error) {
	return model.Application{}, nil
}
func (m *mockAppRepo) GetAppsWithUserCount() ([]response.AppStatsResponse, error) { return nil, nil }
func (m *mockAppRepo) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return nil, nil
}

type mockUserRepo struct {
	user                 model.User
	err                  error
	verifyEmailByTokenFn func(tokenHash []byte) (uint, uint, error)
}

func (m *mockUserRepo) FindAll() ([]model.User, error)                                   { return nil, nil }
func (m *mockUserRepo) CreateWithProfile(user *model.User, profile *model.Profile) error { return nil }
func (m *mockUserRepo) VerifyUserEmail(userID uint, verificationID uint) error           { return nil }
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
func (m *mockUserRepo) UpdateColumn(column string, value interface{}, id uint) error { return nil }
func (m *mockUserRepo) LockUserForUpdate(userID uint) error                          { return nil }

type mockUARRepo struct {
	roles                map[uint][]string
	hasAdminRoleInAnyApp *bool
}

func (m *mockUARRepo) AssignRole(userID, appID, roleID uint) error { return nil }
func (m *mockUARRepo) RevokeAccess(userID, appID uint) error       { return nil }
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
func (m *mockUARRepo) GetUserRolesInApp(userID, appID uint) ([]string, error) {
	return m.roles[userID], nil
}
func (m *mockUARRepo) GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error) {
	return nil, nil
}
func (m *mockUARRepo) GetUsersWithRolesByAppPaginated(appID uint, page, limit int) ([]response.UserAppRow, int64, error) {
	return nil, 0, nil
}
func (m *mockUARRepo) BelongsToApp(userID, appID uint) (bool, error) { return true, nil }
func (m *mockUARRepo) IsAppAdmin(userID, appID uint) (bool, error)   { return true, nil }
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
func (m *mockRuleRepo) CreateDefaultRules(appID uint) error                       { return nil }
func (m *mockRuleRepo) CreateRule(appID uint, code string, val []byte) error      { return nil }
func (m *mockRuleRepo) UpdateRuleValue(appID uint, code string, val []byte) error { return nil }
func (m *mockRuleRepo) DeleteRule(appID uint, code string) error                  { return nil }

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

func (m *mockRefreshTokenRepo) FindActiveByUser(userID uint) ([]model.RefreshToken, error) {
	var list []model.RefreshToken
	for _, t := range m.tokens {
		if t.UserID == userID {
			list = append(list, *t)
		}
	}
	return list, nil
}

func (m *mockRefreshTokenRepo) DeleteByIDAndUser(id uint, userID uint) error {
	for k, t := range m.tokens {
		if t.ID == id && t.UserID == userID {
			delete(m.tokens, k)
			return nil
		}
	}
	return gorm.ErrRecordNotFound
}

func (m *mockRefreshTokenRepo) DeleteOthersByUser(userID uint, currentTokenHash string) error {
	for k, t := range m.tokens {
		if t.UserID == userID && t.Token != currentTokenHash {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *mockRefreshTokenRepo) DeleteOthersByID(userID uint, sessionID uint) error {
	for k, t := range m.tokens {
		if t.UserID == userID && t.ID != sessionID {
			delete(m.tokens, k)
		}
	}
	return nil
}

func (m *mockRefreshTokenRepo) UpdateLastUsed(tokenHash string, ip string) error {
	if t, ok := m.tokens[tokenHash]; ok {
		t.LastUsedAt = time.Now()
		if ip != "" {
			t.IPAddress = ip
		}
	}
	return nil
}

func (m *mockRefreshTokenRepo) DeleteByUserAppAndDevice(userID, appID uint, ip, userAgent string) error {
	for k, t := range m.tokens {
		if t.UserID == userID && t.ApplicationID == appID && (ip == "" || t.IPAddress == ip) && (userAgent == "" || t.UserAgent == userAgent) {
			delete(m.tokens, k)
		}
	}
	return nil
}

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


type mockSetupRepo struct {
	firstRun bool
	err      error
}

func (m *mockSetupRepo) IsFirstRun() (bool, error) {
	return m.firstRun, m.err
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

type mockRoleRepo struct {
	roles      []*model.Role
	userCounts map[uint]int64
	nextID     uint
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{
		roles:      make([]*model.Role, 0),
		userCounts: make(map[uint]int64),
	}
}

func (m *mockRoleRepo) FindByRoleName(roleName string) (model.Role, error) {
	return m.FindGlobalByName(roleName)
}

func (m *mockRoleRepo) FindGlobalByName(roleName string) (model.Role, error) {
	name := strings.ToUpper(roleName)
	for _, r := range m.roles {
		if r.ApplicationID == nil && strings.EqualFold(r.Name, name) {
			return *r, nil
		}
	}
	return model.Role{}, errors.New("rol no encontrado")
}

func (m *mockRoleRepo) FindByNameForApp(roleName string, appID uint) (model.Role, error) {
	name := strings.ToUpper(roleName)
	for _, r := range m.roles {
		if r.ApplicationID != nil && *r.ApplicationID == appID && strings.EqualFold(r.Name, name) {
			return *r, nil
		}
	}
	for _, r := range m.roles {
		if r.ApplicationID == nil && strings.EqualFold(r.Name, name) {
			return *r, nil
		}
	}
	return model.Role{}, errors.New("rol no encontrado")
}

func (m *mockRoleRepo) FindByID(roleID uint) (model.Role, error) {
	for _, r := range m.roles {
		if r.ID == roleID {
			return *r, nil
		}
	}
	return model.Role{}, errors.New("rol no encontrado")
}

func (m *mockRoleRepo) Create(role *model.Role) error {
	m.nextID++
	role.ID = m.nextID
	rCopy := *role
	m.roles = append(m.roles, &rCopy)
	return nil
}

func (m *mockRoleRepo) FindAll() ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		if r.ApplicationID == nil {
			list = append(list, *r)
		}
	}
	return list, nil
}

func (m *mockRoleRepo) FindVisibleForApp(appID uint) ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		if r.ApplicationID == nil || (r.ApplicationID != nil && *r.ApplicationID == appID) {
			list = append(list, *r)
		}
	}
	return list, nil
}

func (m *mockRoleRepo) CountUsersWithRole(roleID uint) (int64, error) {
	return m.userCounts[roleID], nil
}

func (m *mockRoleRepo) Delete(roleID uint) error {
	for i, r := range m.roles {
		if r.ID == roleID {
			m.roles = append(m.roles[:i], m.roles[i+1:]...)
			return nil
		}
	}
	return errors.New("rol no encontrado")
}



