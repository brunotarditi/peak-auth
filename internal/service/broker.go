package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"peak-auth/internal/auth"
	"peak-auth/internal/auth/broker"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"strings"
	"time"

	"gorm.io/gorm"
)

type BrokerAuthResult struct {
	User             *model.User
	Relay            *broker.RelayState
	MfaRequired      bool
	MfaSetupRequired bool
	MfaToken         string
	RedirectURL      string
}

type BrokerService interface {
	GetAuthURL(provider string, relay broker.RelayState) (string, error)
	ProcessCallback(ctx context.Context, provider string, code string, rawState string) (*BrokerAuthResult, error)
	IsProviderConfigured(provider string) bool
	ListConfiguredProviders() []string
}

type brokerService struct {
	identityRepo repo.UserIdentityRepository
	userRepo     repo.UserRepository
	roleRepo     repo.RoleRepository
	uarRepo      repo.UserApplicationRoleRepository
	appRepo      repo.ApplicationRepository
	ruleService  ApplicationRuleService
	tokenManager *auth.JWTManager
	registry     *broker.Registry
	stateSecret  string
}

func NewBrokerService(
	identityRepo repo.UserIdentityRepository,
	userRepo repo.UserRepository,
	roleRepo repo.RoleRepository,
	uarRepo repo.UserApplicationRoleRepository,
	appRepo repo.ApplicationRepository,
	ruleService ApplicationRuleService,
	tokenManager *auth.JWTManager,
	registry *broker.Registry,
	stateSecret string,
) BrokerService {
	return &brokerService{
		identityRepo: identityRepo,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		uarRepo:      uarRepo,
		appRepo:      appRepo,
		ruleService:  ruleService,
		tokenManager: tokenManager,
		registry:     registry,
		stateSecret:  stateSecret,
	}
}

func (s *brokerService) IsProviderConfigured(provider string) bool {
	return s.registry.IsConfigured(provider)
}

func (s *brokerService) ListConfiguredProviders() []string {
	return s.registry.ListAvailable()
}

func (s *brokerService) GetAuthURL(provider string, relay broker.RelayState) (string, error) {
	p, err := s.registry.Get(provider)
	if err != nil {
		return "", err
	}

	if relay.ClientID == "" || relay.RedirectURI == "" {
		return "", errors.New("client_id y redirect_uri son requeridos")
	}

	app, err := s.appRepo.FindByAppID(relay.ClientID)
	if err != nil {
		return "", errors.New("aplicación solicitante no encontrada")
	}
	if !app.IsActive {
		return "", errors.New("la aplicación solicitante está desactivada")
	}

	if err := ValidateRedirectURISecurity(relay.RedirectURI); err != nil {
		return "", fmt.Errorf("redirect_uri inválida: %w", err)
	}

	relay.Provider = provider
	signedState, err := broker.GenerateRelayState(relay, s.stateSecret)
	if err != nil {
		return "", fmt.Errorf("error generando estado de relay: %w", err)
	}

	return p.GetAuthURL(signedState), nil
}

func (s *brokerService) ProcessCallback(ctx context.Context, provider string, code string, rawState string) (*BrokerAuthResult, error) {
	if code == "" {
		return nil, errors.New("código de autorización ausente en la respuesta del proveedor")
	}

	relay, err := broker.ValidateRelayState(rawState, s.stateSecret, 10*time.Minute)
	if err != nil {
		if errors.Is(err, broker.ErrExpiredState) {
			return nil, errors.New("la sesión de autenticación social ha expirado; por favor intente nuevamente")
		}
		return nil, errors.New("el estado de autorización es inválido o fue alterado")
	}

	p, err := s.registry.Get(provider)
	if err != nil {
		return nil, err
	}

	profile, err := p.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("error al intercambiar credenciales con %s: %w", provider, err)
	}

	app, err := s.appRepo.FindByAppID(relay.ClientID)
	if err != nil {
		return nil, errors.New("aplicación solicitante no encontrada")
	}
	if !app.IsActive {
		return nil, errors.New("la aplicación solicitante está desactivada")
	}

	// 1. Resolver usuario mediante Account Linking
	user, err := s.resolveOrCreateUser(profile, &app)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, errors.New("tu cuenta de usuario se encuentra desactivada")
	}

	// 2. Verificar MFA
	mfaRequired := false
	mfaSetupRequired := false
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == util.MFA_POLICY {
				policy, perr := util.ParseMfaPolicy(r.Value)
				if perr == nil && policy.Mode == "REQUIRED" {
					mfaRequired = true
					break
				}
			}
		}
	}

	if user.MfaEnabled {
		mfaRequired = true
	} else if mfaRequired {
		mfaSetupRequired = true
	}

	result := &BrokerAuthResult{
		User:             user,
		Relay:            relay,
		MfaRequired:      mfaRequired,
		MfaSetupRequired: mfaSetupRequired,
	}

	if mfaRequired {
		mfaToken, err := s.tokenManager.GenerateMFAPendingToken(user.ID, user.Email, relay.ClientID)
		if err != nil {
			return nil, fmt.Errorf("error generando token MFA: %w", err)
		}
		result.MfaToken = mfaToken

		targetPath := "/oauth/login/mfa"
		if mfaSetupRequired {
			targetPath = "/oauth/login/mfa/setup"
		}
		mfaURL := url.URL{Path: targetPath}
		q := mfaURL.Query()
		q.Set("client_id", relay.ClientID)
		q.Set("redirect_uri", relay.RedirectURI)
		q.Set("state", relay.State)
		if relay.CodeChallenge != "" {
			q.Set("code_challenge", relay.CodeChallenge)
			q.Set("code_challenge_method", relay.CodeChallengeMethod)
		}
		mfaURL.RawQuery = q.Encode()
		result.RedirectURL = mfaURL.String()
		return result, nil
	}

	// Si no requiere MFA, la URL de destino es /oauth/authorize para completar el flujo SSO
	authURL := url.URL{Path: "/oauth/authorize"}
	q := authURL.Query()
	q.Set("client_id", relay.ClientID)
	q.Set("redirect_uri", relay.RedirectURI)
	q.Set("response_type", "code")
	q.Set("state", relay.State)
	if relay.CodeChallenge != "" {
		q.Set("code_challenge", relay.CodeChallenge)
		q.Set("code_challenge_method", relay.CodeChallengeMethod)
	}
	authURL.RawQuery = q.Encode()
	result.RedirectURL = authURL.String()

	return result, nil
}

func (s *brokerService) resolveOrCreateUser(profile *broker.BrokerProfile, app *model.Application) (*model.User, error) {
	// A. Buscar identidad social existente
	identity, err := s.identityRepo.FindByProviderAndUID(profile.Provider, profile.ProviderUserID)
	if err == nil && identity != nil {
		_ = s.identityRepo.UpdateLastLogin(identity.ID)
		user, uerr := s.userRepo.FindById(identity.UserID)
		if uerr != nil {
			return nil, fmt.Errorf("error cargando usuario asociado: %w", uerr)
		}

		if err := s.ensureUserInApp(user.ID, app); err != nil {
			return nil, err
		}

		// Actualizar avatar si el usuario no tenía uno propio y el proveedor aporta uno
		if user.Profile.AvatarURL == "" && profile.AvatarURL != "" {
			_ = s.userRepo.UpdateAvatar(user.ID, profile.AvatarURL)
			user.Profile.AvatarURL = profile.AvatarURL
		}

		return &user, nil
	}

	// B. La identidad externa no existe. Buscar si ya existe un usuario con este email en Peak Auth
	existingUser, err := s.userRepo.FindByEmail(profile.Email)
	if err == nil {
		// B.1. Vincular la nueva identidad al usuario existente (Account Linking)
		newIdent := model.UserIdentity{
			UserID:         existingUser.ID,
			Provider:       profile.Provider,
			ProviderUserID: profile.ProviderUserID,
			Email:          profile.Email,
			AvatarURL:      profile.AvatarURL,
			LastLoginAt:    time.Now(),
		}
		if cerr := s.identityRepo.Create(&newIdent); cerr != nil {
			return nil, fmt.Errorf("error vinculando identidad externa: %w", cerr)
		}

		if !existingUser.IsVerified {
			_ = s.userRepo.UpdateColumn("is_verified", true, existingUser.ID)
			existingUser.IsVerified = true
		}

		if existingUser.Profile.AvatarURL == "" && profile.AvatarURL != "" {
			_ = s.userRepo.UpdateAvatar(existingUser.ID, profile.AvatarURL)
			existingUser.Profile.AvatarURL = profile.AvatarURL
		}

		if err := s.ensureUserInApp(existingUser.ID, app); err != nil {
			return nil, err
		}

		return &existingUser, nil
	}

	// B.2. El usuario es totalmente nuevo: validar política de registro de la app
	rules, rerr := s.ruleService.FindRulesByAppID(app.ID)
	defaultRole := "USER"
	if rerr == nil {
		for _, r := range rules {
			if r.Code == util.REGISTRATION_POLICY {
				regPol, perr := util.ParseRegistrationPolicy(r.Value)
				if perr == nil {
					if regPol.Mode != "public" {
						return nil, errors.New("el registro público está deshabilitado para esta aplicación; consulte con el administrador")
					}
					if regPol.DefaultRole != "" && !strings.EqualFold(regPol.DefaultRole, "ROOT") && !strings.EqualFold(regPol.DefaultRole, "OWNER") {
						defaultRole = regPol.DefaultRole
					}
				}
				break
			}
		}
	}

	// Generar contraseña aleatoria inalcanzable (la cuenta se autenticará vía Google/GitHub)
	randomPassToken, _, err := util.GenerateToken(32)
	if err != nil {
		return nil, fmt.Errorf("error generando credencial base: %w", err)
	}
	passHash, err := util.HashPassword(randomPassToken)
	if err != nil {
		return nil, fmt.Errorf("error procesando credencial base: %w", err)
	}

	newUser := model.User{
		Email:        profile.Email,
		Password:     passHash,
		IsActive:     true,
		IsVerified:   true, // Verificado por el proveedor de identidad
		LastLogin:    time.Now(),
		AuthzVersion: 0,
	}

	userProfile := model.Profile{
		FirstName: profile.FirstName,
		LastName:  profile.LastName,
		AvatarURL: profile.AvatarURL,
	}

	if err := s.userRepo.CreateWithProfile(&newUser, &userProfile); err != nil {
		return nil, fmt.Errorf("error creando usuario federado: %w", err)
	}
	newUser.Profile = userProfile

	// Crear UserIdentity
	newIdent := model.UserIdentity{
		UserID:         newUser.ID,
		Provider:       profile.Provider,
		ProviderUserID: profile.ProviderUserID,
		Email:          profile.Email,
		AvatarURL:      profile.AvatarURL,
		LastLoginAt:    time.Now(),
	}
	if err := s.identityRepo.Create(&newIdent); err != nil {
		return nil, fmt.Errorf("error asociando identidad federada: %w", err)
	}

	// Asignar rol inicial en la app
	role, err := s.roleRepo.FindByNameForApp(defaultRole, app.ID)
	if err != nil {
		// Fallback a rol global USER
		role, err = s.roleRepo.FindGlobalByName("USER")
	}
	if err == nil {
		_ = s.uarRepo.AssignRole(newUser.ID, app.ID, role.ID)
	}

	return &newUser, nil
}

func (s *brokerService) ensureUserInApp(userID uint, app *model.Application) error {
	belongs, err := s.uarRepo.BelongsToApp(userID, app.ID)
	if err == nil && belongs {
		return nil
	}

	// Resolver rol por defecto
	defaultRole := "USER"
	rules, err := s.ruleService.FindRulesByAppID(app.ID)
	if err == nil {
		for _, r := range rules {
			if r.Code == util.REGISTRATION_POLICY {
				regPol, perr := util.ParseRegistrationPolicy(r.Value)
				if perr == nil {
					if regPol.Mode != "public" {
						return errors.New("el acceso para nuevos usuarios está restringido para esta aplicación")
					}
					if regPol.DefaultRole != "" && !strings.EqualFold(regPol.DefaultRole, "ROOT") && !strings.EqualFold(regPol.DefaultRole, "OWNER") {
						defaultRole = regPol.DefaultRole
					}
				}
				break
			}
		}
	}

	role, err := s.roleRepo.FindByNameForApp(defaultRole, app.ID)
	if err != nil {
		role, err = s.roleRepo.FindGlobalByName("USER")
	}
	if err != nil {
		return fmt.Errorf("rol base no configurado para la aplicación: %w", err)
	}

	if err := s.uarRepo.AssignRole(userID, app.ID, role.ID); err != nil && !errors.Is(err, gorm.ErrDuplicatedKey) {
		return fmt.Errorf("error vinculando usuario a la aplicación: %w", err)
	}

	return nil
}
