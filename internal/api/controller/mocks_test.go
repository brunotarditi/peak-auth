package controller

import (
	"fmt"
	"net/http"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type mockAppService struct {
	app                   model.Application
	isRoot                bool
	revoked               bool
	notBelongs            bool
	registeredAccessTimes []*time.Time
	updatedAccessStarts   *time.Time
	updatedAccessExpires  *time.Time
	updatedAccessUserID   uint
	updatedAccessAppID    string
}

func (m *mockAppService) CreateApp(name, description, redirectURL string, isActive bool, ownerID ...uint) (model.Application, string, error) {
	return model.Application{}, "", nil
}
func (m *mockAppService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	return nil
}
func (m *mockAppService) ValidateAppNameUnique(name string) error { return nil }
func (m *mockAppService) RegenerateSecret(appID string) (string, error) {
	return "", nil
}
func (m *mockAppService) RegisterUserInApp(userEmail, roleName string, app *model.Application, accessTime ...*time.Time) error {
	m.registeredAccessTimes = accessTime
	return nil
}
func (m *mockAppService) RevokeUserFromApp(userID, appID uint) error {
	m.revoked = true
	return nil
}
func (m *mockAppService) TransferOwnership(appID string, currentUserID, newOwnerID uint) error {
	return nil
}
func (m *mockAppService) UpdateUserAccessTime(appID string, targetUserID uint, startsAt, expiresAt *time.Time) error {
	m.updatedAccessAppID = appID
	m.updatedAccessUserID = targetUserID
	m.updatedAccessStarts = startsAt
	m.updatedAccessExpires = expiresAt
	return nil
}
func (m *mockAppService) IsRootUser(userID, appID uint) bool { return m.isRoot }
func (m *mockAppService) UserBelongsToApp(userID, appID uint) (bool, error) {
	return !m.notBelongs, nil
}
func (m *mockAppService) GetAppDetails(appID string) (model.Application, error) {
	return m.app, nil
}
func (m *mockAppService) DeleteApp(appID string) error { return nil }
func (m *mockAppService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return nil, nil
}
func (m *mockAppService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return nil, nil
}
func (m *mockAppService) GetAppTheme(appID string) (*model.ApplicationTheme, error) {
	return m.app.Theme, nil
}
func (m *mockAppService) UpdateAppTheme(appID string, theme *model.ApplicationTheme) error {
	m.app.Theme = theme
	return nil
}
func (m *mockAppService) ResetAppTheme(appID string) error {
	m.app.Theme = nil
	return nil
}

type mockUserServiceForStepUp struct {
	service.UserService
	user *model.User
}

func (m *mockUserServiceForStepUp) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.user != nil {
		return m.user, nil
	}
	return nil, fmt.Errorf("usuario no encontrado")
}

type mockMfaServiceForStepUp struct {
	service.MfaService
	mfaEnabled           bool
	disabled             bool
	totpCode             string
	disableErr           error
	finishWebAuthnRegErr error
}

func (m *mockMfaServiceForStepUp) IsMfaEnabled(userID uint) bool {
	return m.mfaEnabled
}

func (m *mockMfaServiceForStepUp) DisableMFA(userID uint) error {
	if m.disableErr != nil {
		return m.disableErr
	}
	m.disabled = true
	return nil
}

func (m *mockMfaServiceForStepUp) FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request, keyName ...string) error {
	if m.finishWebAuthnRegErr != nil {
		return m.finishWebAuthnRegErr
	}
	return nil
}

func (m *mockMfaServiceForStepUp) ListWebAuthnCredentials(userID uint) ([]response.WebAuthnKeyItem, error) {
	return nil, nil
}

func (m *mockMfaServiceForStepUp) DeleteWebAuthnCredential(userID uint, credID uint) error {
	return nil
}

func (m *mockMfaServiceForStepUp) ValidateTOTPCode(userID uint, code string) error {
	if m.totpCode != "" && m.totpCode == code {
		return nil
	}
	return fmt.Errorf("código inválido")
}

func (m *mockMfaServiceForStepUp) ValidateRecoveryCode(userID uint, code string) error {
	return fmt.Errorf("código inválido")
}

func (m *mockMfaServiceForStepUp) SetupTOTP(userID uint, userEmail string) (*response.TOTPSetupResponse, error) {
	return &response.TOTPSetupResponse{Secret: "TEST_MOCK_TOTP_KEY_ONLY"}, nil
}

type mockAppAdminService struct {
	service.ApplicationService
	createAppFn      func(name, description, redirectURL string, isActive bool, ownerID ...uint) (model.Application, string, error)
	updateAppFn      func(appID string, description, redirectURL string, isActive bool) error
	validateUniqueFn func(name string) error
	transferFn       func(appID string, currentUserID, newOwnerID uint) error
}

func (m *mockAppAdminService) ValidateAppNameUnique(name string) error {
	if m.validateUniqueFn != nil {
		return m.validateUniqueFn(name)
	}
	return nil
}

func (m *mockAppAdminService) CreateApp(name, description, redirectURL string, isActive bool, ownerID ...uint) (model.Application, string, error) {
	if m.createAppFn != nil {
		return m.createAppFn(name, description, redirectURL, isActive, ownerID...)
	}
	return model.Application{Name: name, RedirectURL: redirectURL, IsActive: isActive}, "secret123", nil
}

func (m *mockAppAdminService) TransferOwnership(appID string, currentUserID, newOwnerID uint) error {
	if m.transferFn != nil {
		return m.transferFn(appID, currentUserID, newOwnerID)
	}
	return nil
}

func (m *mockAppAdminService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	if m.updateAppFn != nil {
		return m.updateAppFn(appID, description, redirectURL, isActive)
	}
	return nil
}

func (m *mockAppAdminService) GetAppDetails(appID string) (model.Application, error) {
	return model.Application{ID: 1, AppID: appID, Name: "Test App"}, nil
}

type mockRuleAdminService struct {
	service.ApplicationRuleService
	createDefaultRulesFn func(appID uint) error
	createRuleFn         func(appID uint, code string, val []byte) error
	updateRuleValueFn    func(appID uint, code string, val []byte) error
}

func (m *mockRuleAdminService) CreateDefaultRules(appID uint) error {
	if m.createDefaultRulesFn != nil {
		return m.createDefaultRulesFn(appID)
	}
	return nil
}

func (m *mockRuleAdminService) CreateRule(appID uint, code string, val []byte) error {
	if m.createRuleFn != nil {
		return m.createRuleFn(appID, code, val)
	}
	return nil
}

func (m *mockRuleAdminService) UpdateRuleValue(appID uint, code string, val []byte) error {
	if m.updateRuleValueFn != nil {
		return m.updateRuleValueFn(appID, code, val)
	}
	return nil
}

type mockUserDashboardService struct {
	service.UserService
	findVerifiedUserByIDFn func(id uint) (*model.User, error)
	sendResetEmailFn       func(user *model.User, appID uint) error
}

func (m *mockUserDashboardService) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.findVerifiedUserByIDFn != nil {
		return m.findVerifiedUserByIDFn(id)
	}
	return nil, nil
}

func (m *mockUserDashboardService) SendResetEmail(user *model.User, appID uint) error {
	if m.sendResetEmailFn != nil {
		return m.sendResetEmailFn(user, appID)
	}
	return nil
}

type mockAppDashboardService struct {
	service.ApplicationService
	getAppDetailsFn    func(appID string) (model.Application, error)
	userBelongsToAppFn func(userID, appID uint) (bool, error)
}

func (m *mockAppDashboardService) GetAppDetails(appID string) (model.Application, error) {
	if m.getAppDetailsFn != nil {
		return m.getAppDetailsFn(appID)
	}
	app := model.Application{AppID: appID}
	app.ID = 1
	return app, nil
}

func (m *mockAppDashboardService) UserBelongsToApp(userID, appID uint) (bool, error) {
	if m.userBelongsToAppFn != nil {
		return m.userBelongsToAppFn(userID, appID)
	}
	return true, nil
}

type mockUserServiceForVerify struct {
	service.UserService
	verifyEmailFn        func(token string) (uint, uint, error)
	findVerifiedUserFn   func(id uint) (*model.User, error)
	generateResetTokenFn func(userID, appID uint) (string, []byte, error)
}

func (m *mockUserServiceForVerify) VerifyEmail(token string) (uint, uint, error) {
	if m.verifyEmailFn != nil {
		return m.verifyEmailFn(token)
	}
	return 1, 1, nil
}

func (m *mockUserServiceForVerify) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.findVerifiedUserFn != nil {
		return m.findVerifiedUserFn(id)
	}
	return &model.User{ID: id}, nil
}

func (m *mockUserServiceForVerify) GenerateResetToken(userID, appID uint) (string, []byte, error) {
	if m.generateResetTokenFn != nil {
		return m.generateResetTokenFn(userID, appID)
	}
	return "test-reset-token", []byte("hash"), nil
}
