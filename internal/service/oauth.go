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
	if err := ValidateRedirectURISecurity(redirectURI); err != nil {
		return err
	}

	app, err := s.appRepo.FindByAppID(clientID)
	if err != nil {
		return errors.New("client_id inválido")
	}

	if !app.IsActive {
		return errors.New("la aplicación está desactivada")
	}

	// RFC 6749 Section 3.1.2: redirect_uri must match exactly
	if app.RedirectURL != redirectURI {
		return errors.New("redirect_uri no coincide con la registrada")
	}

	return nil
}

// disallowedRedirectSchemes define esquemas de URI peligrosos no permitidos para redirecciones OAuth.
var disallowedRedirectSchemes = map[string]struct{}{
	"javascript": {},
	"data":       {},
	"vbscript":   {},
	"file":       {},
	"about":      {},
	"blob":       {},
}

// ValidateRedirectURISecurity enforces that redirect URIs use HTTPS,
// allows HTTP only for loopback addresses (RFC 8252 section 7.3),
// and allows custom URI schemes for native mobile apps (RFC 8252 section 7.1).
func ValidateRedirectURISecurity(redirectURI string) error {
	if redirectURI == "" {
		return errors.New("redirect_uri no puede estar vacía")
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme == "" {
		return errors.New("redirect_uri inválida: debe ser una URI absoluta válida")
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Prohibir esquemas peligrosos
	if _, blocked := disallowedRedirectSchemes[scheme]; blocked {
		return errors.New("esquema de redirect_uri no permitido por seguridad")
	}

	// RFC 6749 Section 3.1.2: El endpoint de redirección NO debe incluir fragmento
	if parsed.Fragment != "" {
		return errors.New("redirect_uri no debe contener fragmento (#)")
	}

	switch scheme {
	case "https":
		if parsed.Host == "" {
			return errors.New("redirect_uri inválida: host faltante")
		}
		return nil
	case "http":
		host := parsed.Hostname()
		if isLoopbackAddress(host) {
			return nil
		}
		return errors.New("redirect_uri debe usar HTTPS excepto para direcciones locales (loopback)")
	default:
		// Esquemas personalizados (native apps según RFC 8252)
		return nil
	}
}

func isLoopbackAddress(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	// Validación de client binding y expiración ocurre dentro de la transacción antes de consumir
	code, err := s.oauthRepo.GetAndConsumeCodeForClient(codeStr, clientID)
	if err != nil {
		return 0, false, errors.New("código de autorización inválido o ya utilizado")
	}

	// 3. Validación estricta de redirect_uri (RFC 6749 Sección 4.1.3)
	// RFC 6749 Section 4.1.3: redirect_uri must match exactly
	if code.RedirectURI != "" || redirectURI != "" {
		if redirectURI != code.RedirectURI {
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
