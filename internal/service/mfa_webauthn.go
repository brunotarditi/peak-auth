package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthnInstance *webauthn.WebAuthn

func getWebAuthn() (*webauthn.WebAuthn, error) {
	if webAuthnInstance != nil {
		return webAuthnInstance, nil
	}

	baseURL := util.BaseURL()
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parseando APP_BASE_URL: %w", err)
	}

	rpID := u.Hostname()
	rpOrigin := baseURL

	wconfig := &webauthn.Config{
		RPDisplayName: "Peak Auth",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, err
	}
	webAuthnInstance = wa
	return wa, nil
}

// In-memory cache for WebAuthn sessions with automatic TTL expiration
type expiringWebAuthnSession struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

const maxWaSessionCacheSize = 10000

var (
	waSessionCache = make(map[string]expiringWebAuthnSession)
	waSessionMutex sync.RWMutex
)

func init() {
	go cleanupWebAuthnSessions()
}

func cleanupWebAuthnSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		waSessionMutex.Lock()
		now := time.Now()
		for k, v := range waSessionCache {
			if now.After(v.expiresAt) {
				delete(waSessionCache, k)
			}
		}
		waSessionMutex.Unlock()
	}
}

// StoreWebAuthnSession guarda la sesión de WebAuthn temporalmente con TTL de 5 minutos y límite de capacidad
func StoreWebAuthnSession(key string, session *webauthn.SessionData) {
	waSessionMutex.Lock()
	defer waSessionMutex.Unlock()

	// Control de memoria contra ataques DoS (agotamiento de RAM)
	if len(waSessionCache) >= maxWaSessionCacheSize {
		now := time.Now()
		// Purgar expirados primero
		for k, v := range waSessionCache {
			if now.After(v.expiresAt) {
				delete(waSessionCache, k)
			}
		}
		// Si aún supera el umbral, desalojar la primera entrada arbitraria
		if len(waSessionCache) >= maxWaSessionCacheSize {
			for k := range waSessionCache {
				delete(waSessionCache, k)
				break
			}
		}
	}

	waSessionCache[key] = expiringWebAuthnSession{
		data:      session,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
}

// GetWebAuthnSession recupera la sesión de WebAuthn si no ha expirado
func GetWebAuthnSession(key string) (*webauthn.SessionData, bool) {
	waSessionMutex.RLock()
	defer waSessionMutex.RUnlock()
	session, exists := waSessionCache[key]
	if !exists || time.Now().After(session.expiresAt) {
		return nil, false
	}
	return session.data, true
}

// DeleteWebAuthnSession elimina la sesión de WebAuthn
func DeleteWebAuthnSession(key string) {
	waSessionMutex.Lock()
	defer waSessionMutex.Unlock()
	delete(waSessionCache, key)
}

// webAuthnUserWrapper implementa webauthn.User para interactuar con la librería
type webAuthnUserWrapper struct {
	user        *model.User
	credentials []webauthn.Credential
}

func (u *webAuthnUserWrapper) WebAuthnID() []byte {
	return fmt.Appendf(nil, "%d", u.user.ID)
}

func (u *webAuthnUserWrapper) WebAuthnName() string {
	return u.user.Email
}

func (u *webAuthnUserWrapper) WebAuthnDisplayName() string {
	return u.user.Email
}

func (u *webAuthnUserWrapper) WebAuthnIcon() string {
	return ""
}

func (u *webAuthnUserWrapper) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// BeginWebAuthnRegistration inicia el proceso de registro de una nueva llave
func (s *mfaService) BeginWebAuthnRegistration(userID uint, userEmail string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	wa, err := getWebAuthn()
	if err != nil {
		return nil, nil, fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("usuario no encontrado")
	}

	// Obtener credenciales existentes para excluirlas (así no registra la misma llave dos veces)
	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	options, sessionData, err := wa.BeginRegistration(
		wUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error iniciando registro WebAuthn: %w", err)
	}

	return options, sessionData, nil
}

// FinishWebAuthnRegistration finaliza el registro, guarda la credencial y activa MFA
func (s *mfaService) FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request) error {
	if session == nil {
		return fmt.Errorf("sesión WebAuthn inválida o expirada")
	}

	wa, err := getWebAuthn()
	if err != nil {
		return fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return fmt.Errorf("usuario no encontrado")
	}

	wUser := &webAuthnUserWrapper{
		user: &user,
	}

	credential, err := wa.FinishRegistration(wUser, *session, r)
	if err != nil {
		return fmt.Errorf("error validando registro WebAuthn: %w", err)
	}

	// Serializar credencial a JSON
	credJSON, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("error guardando credencial WebAuthn: %w", err)
	}

	// Guardar en base de datos
	newCred := &model.UserMfaCredential{
		UserID:   userID,
		Type:     "WEBAUTHN",
		Name:     "Llave de Seguridad Passkey",
		Secret:   string(credJSON),
		IsActive: true,
	}

	if err := s.mfaRepo.CreateCredential(newCred); err != nil {
		return fmt.Errorf("error creando registro de credencial WebAuthn en BD: %w", err)
	}

	// Activar MFA en el usuario
	s.userRepo.UpdateColumn("mfa_enabled", true, userID)

	// Generar códigos de recuperación de respaldo si no tiene
	codes, _ := s.mfaRepo.FindUnusedRecoveryCodesByUser(userID)
	if len(codes) == 0 {
		_, _ = s.generateAndSaveRecoveryCodes(userID)
	}

	return nil
}

// BeginWebAuthnLogin inicia el challenge para iniciar sesión
func (s *mfaService) BeginWebAuthnLogin(userID uint) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	wa, err := getWebAuthn()
	if err != nil {
		return nil, nil, fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("usuario no encontrado")
	}

	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	if len(waCreds) == 0 {
		return nil, nil, fmt.Errorf("no hay llaves de seguridad configuradas para este usuario")
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	options, sessionData, err := wa.BeginLogin(wUser)
	if err != nil {
		return nil, nil, fmt.Errorf("error iniciando login WebAuthn: %w", err)
	}

	return options, sessionData, nil
}

// FinishWebAuthnLogin verifica el challenge firmado
func (s *mfaService) FinishWebAuthnLogin(userID uint, session *webauthn.SessionData, r *http.Request) error {
	wa, err := getWebAuthn()
	if err != nil {
		return fmt.Errorf("error inicializando WebAuthn: %w", err)
	}

	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return fmt.Errorf("usuario no encontrado")
	}

	var waCreds []webauthn.Credential
	creds, _ := s.mfaRepo.FindAllCredentialsByUser(userID)
	for _, c := range creds {
		if c.Type == "WEBAUTHN" && c.IsActive {
			var cred webauthn.Credential
			if err := json.Unmarshal([]byte(c.Secret), &cred); err == nil {
				waCreds = append(waCreds, cred)
			}
		}
	}

	wUser := &webAuthnUserWrapper{
		user:        &user,
		credentials: waCreds,
	}

	if session == nil {
		return fmt.Errorf("sesión WebAuthn inválida o expirada")
	}

	_, err = wa.FinishLogin(wUser, *session, r)
	if err != nil {
		return fmt.Errorf("validación WebAuthn fallida: %w", err)
	}

	return nil
}
