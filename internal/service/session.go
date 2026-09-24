package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/repo"
)

type SessionDeviceContext struct {
	IPAddress string
	UserAgent string
}

type SessionService interface {
	ListSessions(userID uint, currentToken string, devCtx ...SessionDeviceContext) ([]response.SessionItem, error)
	RevokeSession(userID uint, sessionID uint) error
	RevokeOtherSessions(userID uint, currentToken string, currentSessionID ...uint) error
	ListAuthorizedApps(userID uint) ([]response.AuthorizedAppItem, error)
	RevokeAuthorizedApp(userID uint, clientID string) error
}

type sessionService struct {
	refreshTokenRepo repo.RefreshTokenRepository
	oauthRepo        repo.OAuthRepository
	appRepo          repo.ApplicationRepository
}

func NewSessionService(
	refreshTokenRepo repo.RefreshTokenRepository,
	oauthRepo repo.OAuthRepository,
	appRepo repo.ApplicationRepository,
) SessionService {
	return &sessionService{
		refreshTokenRepo: refreshTokenRepo,
		oauthRepo:        oauthRepo,
		appRepo:          appRepo,
	}
}

func (s *sessionService) ListSessions(userID uint, currentToken string, devCtx ...SessionDeviceContext) ([]response.SessionItem, error) {
	tokens, err := s.refreshTokenRepo.FindActiveByUser(userID)
	if err != nil {
		return nil, fmt.Errorf("error al obtener sesiones activas: %w", err)
	}

	var currentHash string
	if currentToken != "" {
		hash := sha256.Sum256([]byte(currentToken))
		currentHash = hex.EncodeToString(hash[:])
	}

	var targetUA, targetIP string
	if len(devCtx) > 0 {
		targetUA = devCtx[0].UserAgent
		targetIP = devCtx[0].IPAddress
	}

	matchedCurrent := false
	items := make([]response.SessionItem, 0, len(tokens))
	for _, t := range tokens {
		appName := t.Application.Name
		if appName == "" {
			appName = "Peak Auth"
		}
		clientID := t.Application.AppID

		isCurrent := false
		if currentHash != "" && t.Token == currentHash {
			isCurrent = true
			matchedCurrent = true
		} else if !matchedCurrent && currentHash == "" && targetUA != "" && t.UserAgent == targetUA {
			// Si no hay token explícito pero el User-Agent coincide con el dispositivo actual
			if targetIP == "" || t.IPAddress == targetIP {
				isCurrent = true
				matchedCurrent = true
			}
		}

		deviceType := t.DeviceType
		if deviceType == "" {
			deviceType = "Desktop"
		}

		lastUsed := t.LastUsedAt
		if lastUsed.IsZero() {
			lastUsed = t.CreatedAt
		}

		items = append(items, response.SessionItem{
			ID:         t.ID,
			AppName:    appName,
			ClientID:   clientID,
			IPAddress:  t.IPAddress,
			UserAgent:  t.UserAgent,
			DeviceType: deviceType,
			LastUsedAt: lastUsed,
			CreatedAt:  t.CreatedAt,
			ExpiresAt:  t.ExpiresAt,
			IsCurrent:  isCurrent,
		})
	}

	return items, nil
}

func (s *sessionService) RevokeSession(userID uint, sessionID uint) error {
	if sessionID == 0 {
		return errors.New("identificador de sesión inválido")
	}
	return s.refreshTokenRepo.DeleteByIDAndUser(sessionID, userID)
}

func (s *sessionService) RevokeOtherSessions(userID uint, currentToken string, currentSessionID ...uint) error {
	if currentToken != "" {
		hash := sha256.Sum256([]byte(currentToken))
		currentHash := hex.EncodeToString(hash[:])
		return s.refreshTokenRepo.DeleteOthersByUser(userID, currentHash)
	}

	if len(currentSessionID) > 0 && currentSessionID[0] > 0 {
		return s.refreshTokenRepo.DeleteOthersByID(userID, currentSessionID[0])
	}

	// Si no hay ninguna sesión específica a preservar (ej: el usuario está en el panel web admin con cookie de sesión),
	// se revocan todas las sesiones/tokens de aplicaciones activas del usuario.
	return s.refreshTokenRepo.DeleteByUser(userID)
}

func (s *sessionService) ListAuthorizedApps(userID uint) ([]response.AuthorizedAppItem, error) {
	consents, err := s.oauthRepo.FindConsentsByUser(userID)
	if err != nil {
		return nil, fmt.Errorf("error al obtener aplicaciones autorizadas: %w", err)
	}

	items := make([]response.AuthorizedAppItem, 0, len(consents))
	for _, c := range consents {
		appName := c.Application.Name
		if appName == "" {
			appName = c.ClientID
		}
		items = append(items, response.AuthorizedAppItem{
			ClientID:    c.ClientID,
			AppName:     appName,
			Description: c.Application.Description,
			GrantedAt:   c.GrantedAt,
			ExpiresAt:   c.ExpiresAt,
		})
	}

	return items, nil
}

func (s *sessionService) RevokeAuthorizedApp(userID uint, clientID string) error {
	if clientID == "" {
		return errors.New("client_id requerido")
	}

	// 1. Revocar consentimiento OAuth
	if err := s.oauthRepo.RevokeConsent(userID, clientID); err != nil {
		return fmt.Errorf("error al revocar consentimiento: %w", err)
	}

	// 2. Revocar tokens de sesión asociados a esa app si existe
	app, err := s.appRepo.FindByAppID(clientID)
	if err == nil && app.ID != 0 {
		_ = s.refreshTokenRepo.DeleteByUserAndApp(userID, app.ID)
	}

	return nil
}
