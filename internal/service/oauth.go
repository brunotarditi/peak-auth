package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strings"
	"time"
)

type OAuthService interface {
	ValidateClientRedirect(clientID, redirectURI string) error
	GenerateAuthorizationCode(userID uint, clientID, redirectURI, codeChallenge, codeChallengeMethod string, mfaCompleted bool) (string, error)
	ExchangeCodeForToken(clientID, clientSecret, codeStr, redirectURI, codeVerifier string) (uint, bool, error)
	StartCleanupTask(interval time.Duration)
	HasValidConsent(userID uint, clientID string) (bool, error)
	GrantConsent(userID uint, clientID string) error
}

type oauthService struct {
	oauthRepo repo.OAuthRepository
	appRepo   repo.ApplicationRepository
}

func NewOAuthService(oauthRepo repo.OAuthRepository, appRepo repo.ApplicationRepository) OAuthService {
	return &oauthService{
		oauthRepo: oauthRepo,
		appRepo:   appRepo,
	}
}

func (s *oauthService) ValidateClientRedirect(clientID, redirectURI string) error {
	app, err := s.appRepo.FindByAppID(clientID)
	if err != nil {
		return errors.New("client_id inválido")
	}

	if !app.IsActive {
		return errors.New("la aplicación está desactivada")
	}

	cleanAppURL := strings.TrimRight(strings.TrimSpace(app.RedirectURL), "/")
	cleanReqURL := strings.TrimRight(strings.TrimSpace(redirectURI), "/")
	if cleanAppURL != cleanReqURL {
		return errors.New("redirect_uri no coincide con la registrada")
	}

	// Validate that the redirect URI uses HTTPS or is a loopback HTTP URI
	// This prevents authorization codes from being transmitted over unencrypted connections
	if err := validateRedirectURISecurity(cleanReqURL); err != nil {
		return err
	}

	return nil
}

// validateRedirectURISecurity ensures redirect URIs use HTTPS except for loopback addresses
// Per OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)
func validateRedirectURISecurity(redirectURI string) error {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("redirect_uri tiene formato inválido")
	}

	scheme := strings.ToLower(parsedURL.Scheme)

	// HTTPS is always allowed
	if scheme == "https" {
		return nil
	}

	// HTTP is only allowed for loopback addresses (localhost exception)
	if scheme == "http" {
		host := parsedURL.Hostname()
		if isLoopbackAddress(host) {
			return nil
		}
		return errors.New("redirect_uri debe usar HTTPS excepto para direcciones loopback")
	}

	// Other schemes (custom URI schemes) are not supported for web-based OAuth
	return errors.New("redirect_uri debe usar HTTPS o HTTP para loopback")
}

// isLoopbackAddress checks if a hostname is a loopback address
func isLoopbackAddress(host string) bool {
	// Check for localhost
	if strings.ToLower(host) == "localhost" {
		return true
	}

	// Parse as IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}

	return false
}

func (s *oauthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI, codeChallenge, codeChallengeMethod string, mfaCompleted bool) (string, error) {
	// Verificar que el app existe y que la redirect URI coincide exactamente
	if err := s.ValidateClientRedirect(clientID, redirectURI); err != nil {
		return "", err
	}

	// Normalizar método PKCE si hay challenge
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain"
		}
		methodUpper := strings.ToUpper(codeChallengeMethod)
		if methodUpper != "S256" && methodUpper != "PLAIN" {
			return "", errors.New("code_challenge_method no soportado (use S256 o plain)")
		}
		codeChallengeMethod = methodUpper
	}

	// Generar código aleatorio seguro (32 bytes = 43 caracteres base64)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	codeStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	// Crear el registro en base de datos con un TTL de 5 minutos
	code := &model.OAuthCode{
		Code:                codeStr,
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		MfaCompleted:        mfaCompleted,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	if err := s.oauthRepo.CreateCode(code); err != nil {
		return "", err
	}

	return codeStr, nil
}

func (s *oauthService) ExchangeCodeForToken(clientID, clientSecret, codeStr, redirectURI, codeVerifier string) (uint, bool, error) {
	// 1. Validar las credenciales del cliente (app)
	if clientSecret != "" {
		_, err := s.appRepo.ValidateSecret(clientID, clientSecret)
		if err != nil {
			return 0, false, errors.New("credenciales de cliente inválidas")
		}
	} else {
		// Cliente público (método auth "none"): verificar existencia y estado activo de la app
		app, err := s.appRepo.FindByAppID(clientID)
		if err != nil {
			return 0, false, errors.New("credenciales de cliente inválidas")
		}
		if !app.IsActive {
			return 0, false, errors.New("la aplicación está desactivada")
		}
	}

	// 2. Obtener y consumir el código de un solo uso (One-Time Use Transactional)
	code, err := s.oauthRepo.GetAndConsumeCode(codeStr)
	if err != nil {
		return 0, false, errors.New("código de autorización inválido o ya utilizado")
	}

	// 3. Verificar expiración (por si no lo agarró el cleanup)
	if time.Now().After(code.ExpiresAt) {
		return 0, false, errors.New("el código de autorización ha expirado")
	}

	// 4. Verificar que pertenece a este client_id
	if code.ClientID != clientID {
		return 0, false, errors.New("el código no pertenece a este client_id")
	}

	// 5. Validación estricta de redirect_uri (RFC 6749 Sección 4.1.3)
	if code.RedirectURI != "" || redirectURI != "" {
		cleanRedirectReq := strings.TrimRight(strings.TrimSpace(redirectURI), "/")
		cleanRedirectCode := strings.TrimRight(strings.TrimSpace(code.RedirectURI), "/")
		if cleanRedirectReq != cleanRedirectCode {
			return 0, false, errors.New("redirect_uri no coincide con la asociada al código de autorización")
		}
	}

	// 6. Validación de PKCE (RFC 7636) y requerimiento para clientes públicos
	if clientSecret == "" && code.CodeChallenge == "" {
		return 0, false, errors.New("se requiere client_secret para códigos de autorización sin PKCE")
	}

	if code.CodeChallenge != "" {
		if codeVerifier == "" {
			return 0, false, errors.New("code_verifier es requerido para este código de autorización")
		}

		if code.CodeChallengeMethod == "S256" {
			h := sha256.Sum256([]byte(codeVerifier))
			computed := base64.RawURLEncoding.EncodeToString(h[:])
			if subtle.ConstantTimeCompare([]byte(computed), []byte(code.CodeChallenge)) != 1 {
				return 0, false, errors.New("code_verifier inválido")
			}
		} else { // PLAIN
			if subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(code.CodeChallenge)) != 1 {
				return 0, false, errors.New("code_verifier inválido")
			}
		}
	}

	return code.UserID, code.MfaCompleted, nil
}

// StartCleanupTask inicia una goroutine que borra periódicamente los códigos expirados
func (s *oauthService) StartCleanupTask(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			_ = s.oauthRepo.DeleteExpiredCodes()
		}
	}()
}

func (s *oauthService) HasValidConsent(userID uint, clientID string) (bool, error) {
	return s.oauthRepo.HasValidConsent(userID, clientID)
}

func (s *oauthService) GrantConsent(userID uint, clientID string) error {
	// Verify the client exists and is active
	app, err := s.appRepo.FindByAppID(clientID)
	if err != nil {
		return errors.New("client_id inválido")
	}

	if !app.IsActive {
		return errors.New("la aplicación está desactivada")
	}

	consent := &model.UserConsent{
		UserID:        userID,
		ClientID:      clientID,
		ApplicationID: app.ID,
		GrantedAt:     time.Now(),
		ExpiresAt:     nil, // Consent does not expire by default
	}

	return s.oauthRepo.CreateConsent(consent)
}
