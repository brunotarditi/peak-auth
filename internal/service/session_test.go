package service_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"

	"gorm.io/gorm"
)

type mockSessionRefreshTokenRepo struct {
	tokens []model.RefreshToken
}

func (m *mockSessionRefreshTokenRepo) Create(token *model.RefreshToken) error {
	token.ID = uint(len(m.tokens) + 1)
	m.tokens = append(m.tokens, *token)
	return nil
}

func (m *mockSessionRefreshTokenRepo) FindByToken(token string) (model.RefreshToken, error) {
	for _, t := range m.tokens {
		if t.Token == token {
			return t, nil
		}
	}
	return model.RefreshToken{}, gorm.ErrRecordNotFound
}

func (m *mockSessionRefreshTokenRepo) DeleteByToken(token string) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if t.Token != token {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByTokenAtomic(token string) (int64, error) {
	before := len(m.tokens)
	_ = m.DeleteByToken(token)
	return int64(before - len(m.tokens)), nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByUser(userID uint) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if t.UserID != userID {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByUserAndApp(userID, appID uint) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if !(t.UserID == userID && t.ApplicationID == appID) {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByUserAppAndDevice(userID, appID uint, ip, userAgent string) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if !(t.UserID == userID && t.ApplicationID == appID && (ip == "" || t.IPAddress == ip) && (userAgent == "" || t.UserAgent == userAgent)) {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByApp(appID uint) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if t.ApplicationID != appID {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) FindActiveByUser(userID uint) ([]model.RefreshToken, error) {
	var active []model.RefreshToken
	now := time.Now()
	for _, t := range m.tokens {
		if t.UserID == userID && t.ExpiresAt.After(now) {
			active = append(active, t)
		}
	}
	return active, nil
}

func (m *mockSessionRefreshTokenRepo) DeleteByIDAndUser(id uint, userID uint) error {
	for i, t := range m.tokens {
		if t.ID == id && t.UserID == userID {
			m.tokens = append(m.tokens[:i], m.tokens[i+1:]...)
			return nil
		}
	}
	return gorm.ErrRecordNotFound
}

func (m *mockSessionRefreshTokenRepo) DeleteOthersByUser(userID uint, currentTokenHash string) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if t.UserID != userID || t.Token == currentTokenHash {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) DeleteOthersByID(userID uint, sessionID uint) error {
	var remaining []model.RefreshToken
	for _, t := range m.tokens {
		if t.UserID != userID || t.ID == sessionID {
			remaining = append(remaining, t)
		}
	}
	m.tokens = remaining
	return nil
}

func (m *mockSessionRefreshTokenRepo) UpdateLastUsed(tokenHash string, ip string) error {
	for i, t := range m.tokens {
		if t.Token == tokenHash {
			m.tokens[i].LastUsedAt = time.Now()
			if ip != "" {
				m.tokens[i].IPAddress = ip
			}
			return nil
		}
	}
	return nil
}

type mockSessionOAuthRepo struct {
	consents []model.UserConsent
}

func (m *mockSessionOAuthRepo) CreateCode(code *model.OAuthCode) error                                    { return nil }
func (m *mockSessionOAuthRepo) GetAndConsumeCode(codeStr string) (*model.OAuthCode, error)               { return nil, nil }
func (m *mockSessionOAuthRepo) GetAndConsumeCodeForClient(codeStr, clientID string) (*model.OAuthCode, error) {
	return nil, nil
}
func (m *mockSessionOAuthRepo) DeleteExpiredCodes() error { return nil }
func (m *mockSessionOAuthRepo) HasValidConsent(userID uint, clientID string) (bool, error) {
	for _, c := range m.consents {
		if c.UserID == userID && c.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}
func (m *mockSessionOAuthRepo) CreateConsent(consent *model.UserConsent) error {
	m.consents = append(m.consents, *consent)
	return nil
}
func (m *mockSessionOAuthRepo) RevokeConsent(userID uint, clientID string) error {
	var remaining []model.UserConsent
	for _, c := range m.consents {
		if !(c.UserID == userID && c.ClientID == clientID) {
			remaining = append(remaining, c)
		}
	}
	m.consents = remaining
	return nil
}
func (m *mockSessionOAuthRepo) FindConsentsByUser(userID uint) ([]model.UserConsent, error) {
	var list []model.UserConsent
	for _, c := range m.consents {
		if c.UserID == userID {
			list = append(list, c)
		}
	}
	return list, nil
}

type mockSessionAppRepo struct {
	apps []model.Application
}

func (m *mockSessionAppRepo) Create(app *model.Application) error { return nil }
func (m *mockSessionAppRepo) FindByID(id uint) (model.Application, error) {
	for _, a := range m.apps {
		if a.ID == id {
			return a, nil
		}
	}
	return model.Application{}, gorm.ErrRecordNotFound
}
func (m *mockSessionAppRepo) FindByAppID(appID string) (model.Application, error) {
	for _, a := range m.apps {
		if a.AppID == appID {
			return a, nil
		}
	}
	return model.Application{}, gorm.ErrRecordNotFound
}
func (m *mockSessionAppRepo) FindByName(name string) (model.Application, error) {
	for _, a := range m.apps {
		if a.Name == name {
			return a, nil
		}
	}
	return model.Application{}, gorm.ErrRecordNotFound
}
func (m *mockSessionAppRepo) FindAll() ([]model.Application, error)           { return m.apps, nil }
func (m *mockSessionAppRepo) Update(app *model.Application) error            { return nil }
func (m *mockSessionAppRepo) UpdateColumns(id uint, columns map[string]interface{}) error { return nil }
func (m *mockSessionAppRepo) Delete(id uint) error                           { return nil }
func (m *mockSessionAppRepo) ValidateSecret(appID, secret string) (model.Application, error) {
	return model.Application{}, nil
}
func (m *mockSessionAppRepo) GetAppsWithUserCount() ([]response.AppStatsResponse, error) { return nil, nil }
func (m *mockSessionAppRepo) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error) { return nil, nil }

func TestSessionService_ListSessions(t *testing.T) {
	rawToken1 := "plain-refresh-token-1"
	h1 := sha256.Sum256([]byte(rawToken1))
	hash1 := hex.EncodeToString(h1[:])

	rawToken2 := "plain-refresh-token-2"
	h2 := sha256.Sum256([]byte(rawToken2))
	hash2 := hex.EncodeToString(h2[:])

	rtRepo := &mockSessionRefreshTokenRepo{
		tokens: []model.RefreshToken{
			{
				UserID:        1,
				ApplicationID: 10,
				Application:   model.Application{AppID: "app-client-1", Name: "App 1"},
				Token:         hash1,
				IPAddress:     "192.168.1.50",
				UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				DeviceType:    "Desktop",
				ExpiresAt:     time.Now().Add(24 * time.Hour),
			},
			{
				UserID:        1,
				ApplicationID: 20,
				Application:   model.Application{AppID: "app-client-2", Name: "App 2"},
				Token:         hash2,
				IPAddress:     "10.0.0.1",
				UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
				DeviceType:    "Mobile",
				ExpiresAt:     time.Now().Add(48 * time.Hour),
			},
			{
				UserID:        2, // Different user
				ApplicationID: 10,
				Token:         "user-2-token",
				ExpiresAt:     time.Now().Add(24 * time.Hour),
			},
		},
	}
	rtRepo.tokens[0].ID = 1
	rtRepo.tokens[1].ID = 2
	rtRepo.tokens[2].ID = 3

	oauthRepo := &mockSessionOAuthRepo{}
	appRepo := &mockSessionAppRepo{}
	svc := service.NewSessionService(rtRepo, oauthRepo, appRepo)

	// List sessions passing rawToken1 as currentToken
	sessions, err := svc.ListSessions(1, rawToken1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].ID != 1 {
		t.Errorf("expected session 0 ID 1, got %d", sessions[0].ID)
	}
	if sessions[0].AppName != "App 1" {
		t.Errorf("expected App 1, got %s", sessions[0].AppName)
	}
	if sessions[0].DeviceType != "Desktop" {
		t.Errorf("expected Desktop, got %s", sessions[0].DeviceType)
	}
	if !sessions[0].IsCurrent {
		t.Errorf("expected session 0 to be current")
	}

	if sessions[1].ID != 2 {
		t.Errorf("expected session 1 ID 2, got %d", sessions[1].ID)
	}
	if sessions[1].AppName != "App 2" {
		t.Errorf("expected App 2, got %s", sessions[1].AppName)
	}
	if sessions[1].DeviceType != "Mobile" {
		t.Errorf("expected Mobile, got %s", sessions[1].DeviceType)
	}
	if sessions[1].IsCurrent {
		t.Errorf("expected session 1 not to be current")
	}
}

func TestSessionService_RevokeSession(t *testing.T) {
	rtRepo := &mockSessionRefreshTokenRepo{
		tokens: []model.RefreshToken{
			{UserID: 1, Token: "token-1", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	rtRepo.tokens[0].ID = 1

	svc := service.NewSessionService(rtRepo, &mockSessionOAuthRepo{}, &mockSessionAppRepo{})

	err := svc.RevokeSession(1, 0)
	if err == nil {
		t.Fatalf("expected error for ID 0, got nil")
	}

	err = svc.RevokeSession(1, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rtRepo.tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(rtRepo.tokens))
	}
}

func TestSessionService_RevokeOtherSessions(t *testing.T) {
	rawCurrent := "my-active-token"
	h := sha256.Sum256([]byte(rawCurrent))
	hashCurrent := hex.EncodeToString(h[:])

	rtRepo := &mockSessionRefreshTokenRepo{
		tokens: []model.RefreshToken{
			{UserID: 1, Token: hashCurrent, ExpiresAt: time.Now().Add(time.Hour)},
			{UserID: 1, Token: "other-hash-1", ExpiresAt: time.Now().Add(time.Hour)},
			{UserID: 1, Token: "other-hash-2", ExpiresAt: time.Now().Add(time.Hour)},
			{UserID: 2, Token: "user-2-hash", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}

	svc := service.NewSessionService(rtRepo, &mockSessionOAuthRepo{}, &mockSessionAppRepo{})

	// When passing current token, preserves it
	err := svc.RevokeOtherSessions(1, rawCurrent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// User 1 should only have the current token, User 2 untouched
	if len(rtRepo.tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(rtRepo.tokens))
	}
	if rtRepo.tokens[0].Token != hashCurrent {
		t.Errorf("expected current token %s, got %s", hashCurrent, rtRepo.tokens[0].Token)
	}
	if rtRepo.tokens[1].Token != "user-2-hash" {
		t.Errorf("expected user-2-hash, got %s", rtRepo.tokens[1].Token)
	}

	// When passing empty token and no session ID, revokes all user 1 tokens
	err = svc.RevokeOtherSessions(1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rtRepo.tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(rtRepo.tokens))
	}
	if rtRepo.tokens[0].Token != "user-2-hash" {
		t.Errorf("expected user-2-hash, got %s", rtRepo.tokens[0].Token)
	}

	// Test revoking others by session ID
	rtRepo.tokens = []model.RefreshToken{
		{UserID: 1, Token: "t1", ExpiresAt: time.Now().Add(time.Hour)},
		{UserID: 1, Token: "t2", ExpiresAt: time.Now().Add(time.Hour)},
		{UserID: 1, Token: "t3", ExpiresAt: time.Now().Add(time.Hour)},
	}
	rtRepo.tokens[0].ID = 10
	rtRepo.tokens[1].ID = 20
	rtRepo.tokens[2].ID = 30

	err = svc.RevokeOtherSessions(1, "", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rtRepo.tokens) != 1 {
		t.Fatalf("expected 1 token remaining, got %d", len(rtRepo.tokens))
	}
	if rtRepo.tokens[0].ID != 20 {
		t.Errorf("expected token ID 20, got %d", rtRepo.tokens[0].ID)
	}
}

func TestSessionService_ListSessions_DeviceContext(t *testing.T) {
	rtRepo := &mockSessionRefreshTokenRepo{
		tokens: []model.RefreshToken{
			{
				UserID:    1,
				Token:     "tok-1",
				IPAddress: "192.168.1.50",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
				ExpiresAt: time.Now().Add(time.Hour),
				Application: model.Application{
					AppID: "peak-auth",
					Name:  "Peak Auth",
				},
			},
			{
				UserID:    1,
				Token:     "tok-2",
				IPAddress: "10.0.0.1",
				UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
				ExpiresAt: time.Now().Add(time.Hour),
				Application: model.Application{
					AppID: "other-app",
					Name:  "Other App",
				},
			},
		},
	}
	rtRepo.tokens[0].ID = 1
	rtRepo.tokens[1].ID = 2

	svc := service.NewSessionService(rtRepo, &mockSessionOAuthRepo{}, &mockSessionAppRepo{})

	// List without token but with device context matching token 1
	sessions, err := svc.ListSessions(1, "", service.SessionDeviceContext{
		IPAddress: "192.168.1.50",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if !sessions[0].IsCurrent {
		t.Errorf("expected session 0 to be marked current")
	}
	if sessions[1].IsCurrent {
		t.Errorf("expected session 1 not to be current")
	}
}

func TestSessionService_AuthorizedApps(t *testing.T) {
	rtRepo := &mockSessionRefreshTokenRepo{
		tokens: []model.RefreshToken{
			{UserID: 1, ApplicationID: 10, Token: "rt-1"},
		},
	}
	oauthRepo := &mockSessionOAuthRepo{
		consents: []model.UserConsent{
			{
				UserID:        1,
				ClientID:      "my-client-app",
				ApplicationID: 10,
				Application:   model.Application{AppID: "my-client-app", Name: "My Client", Description: "Desc"},
				GrantedAt:     time.Now(),
			},
		},
	}
	appRepo := &mockSessionAppRepo{
		apps: []model.Application{
			{AppID: "my-client-app"},
		},
	}
	appRepo.apps[0].ID = 10

	svc := service.NewSessionService(rtRepo, oauthRepo, appRepo)

	apps, err := svc.ListAuthorizedApps(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].ClientID != "my-client-app" {
		t.Errorf("expected client-id my-client-app, got %s", apps[0].ClientID)
	}
	if apps[0].AppName != "My Client" {
		t.Errorf("expected app name My Client, got %s", apps[0].AppName)
	}

	// Revoke authorized app
	err = svc.RevokeAuthorizedApp(1, "my-client-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(oauthRepo.consents) != 0 {
		t.Errorf("expected 0 consents, got %d", len(oauthRepo.consents))
	}
	if len(rtRepo.tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(rtRepo.tokens))
	}
}
