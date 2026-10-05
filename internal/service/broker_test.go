package service

import (
	"context"
	"errors"
	"peak-auth/internal/auth/broker"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

type mockIdentityRepo struct {
	identities map[string]*model.UserIdentity // key: provider + ":" + uid
}

func newMockIdentityRepo() *mockIdentityRepo {
	return &mockIdentityRepo{
		identities: make(map[string]*model.UserIdentity),
	}
}

func (m *mockIdentityRepo) FindByProviderAndUID(provider, uid string) (*model.UserIdentity, error) {
	key := provider + ":" + uid
	id, exists := m.identities[key]
	if !exists {
		return nil, gorm.ErrRecordNotFound
	}
	return id, nil
}

func (m *mockIdentityRepo) FindByUserID(userID uint) ([]model.UserIdentity, error) {
	var list []model.UserIdentity
	for _, id := range m.identities {
		if id.UserID == userID {
			list = append(list, *id)
		}
	}
	return list, nil
}

func (m *mockIdentityRepo) Create(identity *model.UserIdentity) error {
	key := identity.Provider + ":" + identity.ProviderUserID
	identity.ID = uint(len(m.identities) + 1)
	m.identities[key] = identity
	return nil
}

func (m *mockIdentityRepo) UpdateLastLogin(id uint) error {
	for _, ident := range m.identities {
		if ident.ID == id {
			ident.LastLoginAt = time.Now()
			return nil
		}
	}
	return nil
}

func (m *mockIdentityRepo) Delete(id uint) error {
	for k, ident := range m.identities {
		if ident.ID == id {
			delete(m.identities, k)
			return nil
		}
	}
	return nil
}

type mockBrokerProvider struct {
	name        string
	profile     *broker.BrokerProfile
	exchangeErr error
}

func (m *mockBrokerProvider) ProviderName() string {
	return m.name
}

func (m *mockBrokerProvider) GetAuthURL(state string) string {
	return "https://auth.provider.com/auth?state=" + state
}

func (m *mockBrokerProvider) Exchange(ctx context.Context, code string) (*broker.BrokerProfile, error) {
	if m.exchangeErr != nil {
		return nil, m.exchangeErr
	}
	return m.profile, nil
}

func setupBrokerTest(t *testing.T) (BrokerService, *mockIdentityRepo, *mockUserRepo, *mockAppRepo, *broker.Registry, string) {
	identityRepo := newMockIdentityRepo()
	userRepo := &mockUserRepo{users: make(map[string]*model.User)}
	roleRepo := newMockRoleRepo()
	uarRepo := &mockUARRepo{}
	appRepo := newMockAppRepo()
	ruleRepo := &mockRuleRepo{}
	ruleService := NewApplicationRuleService(ruleRepo, uarRepo, roleRepo, appRepo)

	tokenManager := newServiceTestJWTManager(t)

	registry := broker.NewRegistry(broker.BrokerConfig{})
	stateSecret := "test-broker-state-secret-12345"

	svc := NewBrokerService(
		identityRepo,
		userRepo,
		roleRepo,
		uarRepo,
		appRepo,
		ruleService,
		tokenManager,
		registry,
		stateSecret,
	)

	return svc, identityRepo, userRepo, appRepo, registry, stateSecret
}

func TestBrokerService_GetAuthURL(t *testing.T) {
	svc, _, _, appRepo, registry, _ := setupBrokerTest(t)

	registry.Register(&mockBrokerProvider{name: "google"})
	appRepo.apps["valid-app"] = &model.Application{AppID: "valid-app", RedirectURL: "https://my-app.com/callback", IsActive: true}

	t.Run("Valid app generates signed URL", func(t *testing.T) {
		relay := broker.RelayState{
			ClientID:    "valid-app",
			RedirectURI: "https://my-app.com/callback",
			State:       "oauth-state-123",
		}
		authURL, err := svc.GetAuthURL("google", relay)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(authURL, "https://auth.provider.com/auth?state=") {
			t.Errorf("expected provider auth URL prefix, got %s", authURL)
		}
	})

	t.Run("Inactive app rejected", func(t *testing.T) {
		appRepo.apps["inactive-app"] = &model.Application{AppID: "inactive-app", RedirectURL: "https://my-app.com/callback", IsActive: false}
		relay := broker.RelayState{
			ClientID:    "inactive-app",
			RedirectURI: "https://my-app.com/callback",
		}
		_, err := svc.GetAuthURL("google", relay)
		if err == nil || !strings.Contains(err.Error(), "desactivada") {
			t.Fatalf("expected deactivated error, got %v", err)
		}
	})

	t.Run("Unsupported provider rejected", func(t *testing.T) {
		relay := broker.RelayState{
			ClientID:    "valid-app",
			RedirectURI: "https://my-app.com/callback",
		}
		_, err := svc.GetAuthURL("unsupported", relay)
		if err == nil {
			t.Fatal("expected error for unsupported provider, got nil")
		}
	})
}

func TestBrokerService_ProcessCallback_NewUserCreation(t *testing.T) {
	svc, identityRepo, userRepo, appRepo, registry, stateSecret := setupBrokerTest(t)

	googleProfile := &broker.BrokerProfile{
		Provider:       "google",
		ProviderUserID: "google-uid-100",
		Email:          "newuser@gmail.com",
		FirstName:      "John",
		LastName:       "Doe",
		AvatarURL:      "https://google.com/photo.jpg",
	}
	registry.Register(&mockBrokerProvider{name: "google", profile: googleProfile})

	app := &model.Application{
		Model:       gorm.Model{ID: 10},
		AppID:       "my-app",
		RedirectURL: "https://my-app.com/callback",
		IsActive:    true,
	}
	appRepo.apps["my-app"] = app

	relay := broker.RelayState{
		ClientID:      "my-app",
		RedirectURI:   "https://my-app.com/callback",
		State:         "random-client-state",
		CodeChallenge: "challenge-123",
	}
	rawState, _ := broker.GenerateRelayState(relay, stateSecret)

	res, err := svc.ProcessCallback(context.Background(), "google", "valid-code", rawState)
	if err != nil {
		t.Fatalf("unexpected error processing callback: %v", err)
	}

	if res.User == nil {
		t.Fatal("expected user to be created, got nil")
	}
	if res.User.Email != "newuser@gmail.com" {
		t.Errorf("expected email newuser@gmail.com, got %s", res.User.Email)
	}
	if !res.User.IsVerified {
		t.Error("expected federated user to be verified")
	}

	// Verify identity stored in repo
	ident, err := identityRepo.FindByProviderAndUID("google", "google-uid-100")
	if err != nil || ident == nil {
		t.Fatalf("expected UserIdentity in repo, got err: %v", err)
	}
	if ident.Email != "newuser@gmail.com" {
		t.Errorf("expected identity email newuser@gmail.com, got %s", ident.Email)
	}

	// Verify redirect URL goes to /oauth/authorize with params preserved
	if !strings.Contains(res.RedirectURL, "/oauth/authorize?") {
		t.Errorf("expected redirect to /oauth/authorize, got %s", res.RedirectURL)
	}
	if !strings.Contains(res.RedirectURL, "client_id=my-app") {
		t.Errorf("expected client_id in redirect URL, got %s", res.RedirectURL)
	}
	if !strings.Contains(res.RedirectURL, "state=random-client-state") {
		t.Errorf("expected state in redirect URL, got %s", res.RedirectURL)
	}

	// Ensure user exists in userRepo
	dbUser, err := userRepo.FindByEmail("newuser@gmail.com")
	if err != nil || dbUser.Email != "newuser@gmail.com" {
		t.Errorf("expected user in userRepo, got %v", dbUser)
	}
}

func TestBrokerService_ProcessCallback_AccountLinking(t *testing.T) {
	svc, identityRepo, userRepo, appRepo, registry, stateSecret := setupBrokerTest(t)

	// Pre-exist user with password
	existingUser := &model.User{
		Model:      gorm.Model{ID: 42},
		Email:      "existing@test.com",
		IsActive:   true,
		IsVerified: false, // will be verified on social login
	}
	userRepo.users["existing@test.com"] = existingUser

	githubProfile := &broker.BrokerProfile{
		Provider:       "github",
		ProviderUserID: "github-uid-999",
		Email:          "existing@test.com",
		FirstName:      "Octocat",
		AvatarURL:      "https://github.com/avatar.png",
	}
	registry.Register(&mockBrokerProvider{name: "github", profile: githubProfile})

	app := &model.Application{
		Model:       gorm.Model{ID: 10},
		AppID:       "my-app",
		RedirectURL: "https://my-app.com/callback",
		IsActive:    true,
	}
	appRepo.apps["my-app"] = app

	relay := broker.RelayState{
		ClientID:    "my-app",
		RedirectURI: "https://my-app.com/callback",
		State:       "st-456",
	}
	rawState, _ := broker.GenerateRelayState(relay, stateSecret)

	res, err := svc.ProcessCallback(context.Background(), "github", "valid-code", rawState)
	if err != nil {
		t.Fatalf("unexpected error linking account: %v", err)
	}

	if res.User.ID != 42 {
		t.Errorf("expected user ID 42 (linked), got %d", res.User.ID)
	}

	// Verify UserIdentity was created for existing user ID
	ident, err := identityRepo.FindByProviderAndUID("github", "github-uid-999")
	if err != nil || ident == nil {
		t.Fatalf("expected identity created for GitHub, got %v", err)
	}
	if ident.UserID != 42 {
		t.Errorf("expected identity linked to user 42, got %d", ident.UserID)
	}
}

func TestBrokerService_ProcessCallback_TamperedStateRejected(t *testing.T) {
	svc, _, _, _, registry, _ := setupBrokerTest(t)
	registry.Register(&mockBrokerProvider{name: "google"})

	_, err := svc.ProcessCallback(context.Background(), "google", "valid-code", "tampered.state.string")
	if err == nil || !strings.Contains(err.Error(), "inválido") {
		t.Fatalf("expected invalid state error, got %v", err)
	}
}

func TestBrokerService_ProcessCallback_ExchangeError(t *testing.T) {
	svc, _, _, appRepo, registry, stateSecret := setupBrokerTest(t)
	registry.Register(&mockBrokerProvider{
		name:        "google",
		exchangeErr: errors.New("invalid_grant"),
	})

	appRepo.apps["my-app"] = &model.Application{AppID: "my-app", RedirectURL: "https://my-app.com/callback", IsActive: true}
	rawState, _ := broker.GenerateRelayState(broker.RelayState{ClientID: "my-app", RedirectURI: "https://my-app.com/callback"}, stateSecret)

	_, err := svc.ProcessCallback(context.Background(), "google", "bad-code", rawState)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected exchange error, got %v", err)
	}
}

func TestBrokerService_ProcessCallback_LoginCSRFProtection(t *testing.T) {
	svc, _, _, appRepo, registry, stateSecret := setupBrokerTest(t)
	registry.Register(&mockBrokerProvider{
		name:    "google",
		profile: &broker.BrokerProfile{Provider: "google", ProviderUserID: "123", Email: "u@t.com"},
	})
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app", RedirectURL: "https://my-app.com/cb", IsActive: true}

	rawState, _ := broker.GenerateRelayState(broker.RelayState{
		ClientID:    "my-app",
		RedirectURI: "https://my-app.com/cb",
		Nonce:       "attacker-nonce",
	}, stateSecret)

	// Victim's browser has a different nonce
	_, err := svc.ProcessCallback(context.Background(), "google", "code", rawState, "victim-browser-nonce")
	if err == nil || !strings.Contains(err.Error(), "CSRF") {
		t.Fatalf("expected Login CSRF error, got: %v", err)
	}
}

func TestBrokerService_ProcessCallback_ReplayAttackPrevented(t *testing.T) {
	svc, _, _, appRepo, registry, stateSecret := setupBrokerTest(t)
	registry.Register(&mockBrokerProvider{
		name:    "google",
		profile: &broker.BrokerProfile{Provider: "google", ProviderUserID: "123", Email: "u@t.com"},
	})
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app", RedirectURL: "https://my-app.com/cb", IsActive: true}

	rawState, _ := broker.GenerateRelayState(broker.RelayState{
		ClientID:    "my-app",
		RedirectURI: "https://my-app.com/cb",
		Nonce:       "replayed-nonce",
	}, stateSecret)

	// First execution succeeds
	_, err := svc.ProcessCallback(context.Background(), "google", "code", rawState, "replayed-nonce")
	if err != nil {
		t.Fatalf("first execution should succeed, got: %v", err)
	}

	// Replay attempt fails
	_, err = svc.ProcessCallback(context.Background(), "google", "code", rawState, "replayed-nonce")
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay attack error, got: %v", err)
	}
}

type mockTxRepoForBroker struct {
	repo.TxRepository
	userRepo  repo.UserRepository
	identRepo repo.UserIdentityRepository
	roleRepo  repo.RoleRepository
	uarRepo   repo.UserApplicationRoleRepository
}

func (m *mockTxRepoForBroker) Users() repo.UserRepository               { return m.userRepo }
func (m *mockTxRepoForBroker) Identities() repo.UserIdentityRepository   { return m.identRepo }
func (m *mockTxRepoForBroker) Roles() repo.RoleRepository               { return m.roleRepo }
func (m *mockTxRepoForBroker) UAR() repo.UserApplicationRoleRepository   { return m.uarRepo }

type mockTxManagerForBroker struct {
	txRepo repo.TxRepository
}

func (m *mockTxManagerForBroker) WithinTransaction(fn func(tx repo.TxRepository) error) error {
	return fn(m.txRepo)
}

type mockFailingIdentityRepo struct {
	*mockIdentityRepo
}

func (m *mockFailingIdentityRepo) Create(identity *model.UserIdentity) error {
	return errors.New("database disk full on identities")
}

func TestBrokerService_ProcessCallback_TransactionalRollbackOnIdentityError(t *testing.T) {
	identityRepo := newMockIdentityRepo()
	userRepo := &mockUserRepo{users: make(map[string]*model.User)}
	roleRepo := newMockRoleRepo()
	uarRepo := &mockUARRepo{}
	appRepo := newMockAppRepo()
	ruleRepo := &mockRuleRepo{}
	ruleService := NewApplicationRuleService(ruleRepo, uarRepo, roleRepo, appRepo)
	tokenManager := newServiceTestJWTManager(t)
	registry := broker.NewRegistry(broker.BrokerConfig{})
	stateSecret := "test-broker-state-secret-12345"

	failingIdentRepo := &mockFailingIdentityRepo{mockIdentityRepo: identityRepo}

	txRepo := &mockTxRepoForBroker{
		userRepo:  userRepo,
		identRepo: failingIdentRepo,
		roleRepo:  roleRepo,
		uarRepo:   uarRepo,
	}
	txMgr := &mockTxManagerForBroker{txRepo: txRepo}

	svc := NewBrokerService(
		failingIdentRepo,
		userRepo,
		roleRepo,
		uarRepo,
		appRepo,
		ruleService,
		tokenManager,
		registry,
		stateSecret,
		txMgr,
	)

	registry.Register(&mockBrokerProvider{
		name:    "google",
		profile: &broker.BrokerProfile{Provider: "google", ProviderUserID: "123", Email: "new-user@t.com"},
	})
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app", RedirectURL: "https://my-app.com/cb", IsActive: true}

	rawState, _ := broker.GenerateRelayState(broker.RelayState{
		ClientID:    "my-app",
		RedirectURI: "https://my-app.com/cb",
		Nonce:       "tx-nonce",
	}, stateSecret)

	_, err := svc.ProcessCallback(context.Background(), "google", "code", rawState, "tx-nonce")
	if err == nil || !strings.Contains(err.Error(), "database disk full on identities") {
		t.Fatalf("expected transaction failure error, got: %v", err)
	}
}
