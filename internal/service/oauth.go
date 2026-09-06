package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strings"
	"time"
)

type OAuthService interface {
	ValidateClientRedirect(clientID, redirectURI string) error
	GenerateAuthorizationCode(userID uint, clientID, redirectURI, codeChallenge, codeChallengeMethod string) (string, error)
	ExchangeCodeForToken(clientID, clientSecret, codeStr, redirectURI, codeVerifier string) (uint, error)
	StartCleanupTask(interval time.Duration)
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

	cleanAppURL := strings.TrimRight(strings.TrimSpace(app.RedirectURL), "/")
	cleanReqURL := strings.TrimRight(strings.TrimSpace(redirectURI), "/")
	if cleanAppURL != cleanReqURL {
		return errors.New("redirect_uri no coincide con la registrada")
	}

	return nil
}

func (s *oauthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI, codeChallenge, codeChallengeMethod string) (string, error) {
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
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	if err := s.oauthRepo.CreateCode(code); err != nil {
		return "", err
	}

	return codeStr, nil
}

func (s *oauthService) ExchangeCodeForToken(clientID, clientSecret, codeStr, redirectURI, codeVerifier string) (uint, error) {
	// 1. Validar las credenciales del cliente (app) usando hashing constante de secreto
	_, err := s.appRepo.ValidateSecret(clientID, clientSecret)
	if err != nil {
		return 0, errors.New("credenciales de cliente inválidas")
	}

	// 2. Obtener y consumir el código de un solo uso (One-Time Use Transactional)
	code, err := s.oauthRepo.GetAndConsumeCode(codeStr)
	if err != nil {
		return 0, errors.New("código de autorización inválido o ya utilizado")
	}

	// 3. Verificar expiración (por si no lo agarró el cleanup)
	if time.Now().After(code.ExpiresAt) {
		return 0, errors.New("el código de autorización ha expirado")
	}

	// 4. Verificar que pertenece a este client_id
	if code.ClientID != clientID {
		return 0, errors.New("el código no pertenece a este client_id")
	}

	// 5. Validación estricta de redirect_uri (RFC 6749 Sección 4.1.3)
	if code.RedirectURI != "" || redirectURI != "" {
		cleanRedirectReq := strings.TrimRight(strings.TrimSpace(redirectURI), "/")
		cleanRedirectCode := strings.TrimRight(strings.TrimSpace(code.RedirectURI), "/")
		if cleanRedirectReq != cleanRedirectCode {
			return 0, errors.New("redirect_uri no coincide con la asociada al código de autorización")
		}
	}

	// 6. Validación de PKCE (RFC 7636)
	if code.CodeChallenge != "" {
		if codeVerifier == "" {
			return 0, errors.New("code_verifier es requerido para este código de autorización")
		}

		if code.CodeChallengeMethod == "S256" {
			h := sha256.Sum256([]byte(codeVerifier))
			computed := base64.RawURLEncoding.EncodeToString(h[:])
			if subtle.ConstantTimeCompare([]byte(computed), []byte(code.CodeChallenge)) != 1 {
				return 0, errors.New("code_verifier inválido")
			}
		} else { // PLAIN
			if subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(code.CodeChallenge)) != 1 {
				return 0, errors.New("code_verifier inválido")
			}
		}
	}

	return code.UserID, nil
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
