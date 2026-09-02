package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strings"
	"time"
)

type OAuthService interface {
	GenerateAuthorizationCode(userID uint, clientID, redirectURI string) (string, error)
	ExchangeCodeForToken(clientID, clientSecret, codeStr string) (uint, error)
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

func (s *oauthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI string) (string, error) {
	// Verificar que el app existe y que la redirect URI coincide exactamente
	app, err := s.appRepo.FindByAppID(clientID)
	if err != nil {
		return "", errors.New("client_id inválido")
	}

	cleanAppURL := strings.TrimRight(strings.TrimSpace(app.RedirectURL), "/")
	cleanReqURL := strings.TrimRight(strings.TrimSpace(redirectURI), "/")
	if cleanAppURL != cleanReqURL {
		return "", errors.New("redirect_uri no coincide con la registrada")
	}

	// Generar código aleatorio seguro (32 bytes = 43 caracteres base64)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	codeStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	// Crear el registro en base de datos con un TTL de 5 minutos
	code := &model.OAuthCode{
		Code:        codeStr,
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := s.oauthRepo.CreateCode(code); err != nil {
		return "", err
	}

	return codeStr, nil
}

func (s *oauthService) ExchangeCodeForToken(clientID, clientSecret, codeStr string) (uint, error) {
	// 1. Validar las credenciales del cliente (app)
	app, err := s.appRepo.FindByAppID(clientID)
	if err != nil {
		return 0, errors.New("client_id inválido")
	}

	if app.SecretKey != clientSecret {
		return 0, errors.New("client_secret inválido")
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
