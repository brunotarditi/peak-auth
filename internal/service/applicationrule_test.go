package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"peak-auth/internal/api/request"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"gorm.io/gorm"
)

// --- Tests Application Rule Service ---

func TestValidateRegistration_ForbidsAdminRole(t *testing.T) {
	ruleRepo := &mockRuleRepo{
		rules: []model.ApplicationRules{
			{
				Code:  util.REGISTRATION_POLICY,
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
				Code:  util.REGISTRATION_POLICY,
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

	err := ruleSvc.CreateRule(1, util.REGISTRATION_POLICY, []byte("{\"mode\":\"public\",\"default_role\":\"ADMIN\"}"))
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
				Code:  util.REGISTRATION_POLICY,
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


