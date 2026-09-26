package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Sentinel errors for distinguishing client validation errors from internal errors
var (
	// ErrWebAuthnValidation indicates a client-side validation error (malformed ceremony, invalid signature, etc.)
	ErrWebAuthnValidation = errors.New("registro WebAuthn inválido")
	// ErrWebAuthnInternal indicates an internal/infrastructure error (database, initialization, etc.)
	ErrWebAuthnInternal = errors.New("error interno procesando WebAuthn")
)

// Global repository instance for MFA attempt tracking
// This will be initialized by the application setup
var mfaAttemptRepo repo.MfaAttemptRepository

// InitMfaAttemptTracking initializes the database-backed MFA attempt tracking
func InitMfaAttemptTracking(repo repo.MfaAttemptRepository) {
	mfaAttemptRepo = repo
	// Start background cleanup of expired trackers
	go cleanupExpiredMfaAttempts()
}

func cleanupExpiredMfaAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		if mfaAttemptRepo != nil {
			_ = mfaAttemptRepo.CleanupExpired()
		}
	}
}

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

// GetAndDeleteWebAuthnSession atomically retrieves and deletes a WebAuthn session
// This prevents replay attacks by ensuring the session can only be consumed once
func GetAndDeleteWebAuthnSession(key string) (*webauthn.SessionData, bool) {
	waSessionMutex.Lock()
	defer waSessionMutex.Unlock()

	session, exists := waSessionCache[key]
	if !exists || time.Now().After(session.expiresAt) {
		return nil, false
	}

	// Atomically delete the session before returning it
	delete(waSessionCache, key)
	return session.data, true
}

// MFA Transaction Store - Server-side state for MFA pending flows
// This prevents replay attacks by binding MFA tokens to server-side transactions
// that are consumed on first successful use.

type MfaTransaction struct {
	MfaToken       string    // The actual JWT token (kept server-side only)
	UserID         uint      // User ID from the token
	Username       string    // Username from the token
	AppID          string    // Application ID
	CreatedAt      time.Time // Transaction creation time
	ExpiresAt      time.Time // Transaction expiration (5 minutes)
	Consumed       bool      // Whether this transaction has been used
	SessionCookie  string    // Browser session identifier for binding
	FailedAttempts int       // Counter for failed MFA validation attempts
	Locked         bool      // Whether this transaction is locked due to excessive failures
}

const maxMfaTransactionCacheSize = 10000

var (
	mfaTransactionCache = make(map[string]*MfaTransaction)
	mfaTransactionMutex sync.RWMutex
)

func init() {
	go cleanupMfaTransactions()
}

func cleanupMfaTransactions() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		mfaTransactionMutex.Lock()
		now := time.Now()
		for k, v := range mfaTransactionCache {
			if now.After(v.ExpiresAt) {
				delete(mfaTransactionCache, k)
			}
		}
		mfaTransactionMutex.Unlock()
	}
}

// generateTransactionID creates a cryptographically secure random transaction ID
func generateTransactionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreMfaTransaction creates a server-side MFA transaction and returns an opaque transaction ID
func StoreMfaTransaction(mfaToken string, userID uint, username string, appID string, sessionCookie string) (string, error) {
	mfaTransactionMutex.Lock()
	defer mfaTransactionMutex.Unlock()

	// Control de memoria contra ataques DoS
	if len(mfaTransactionCache) >= maxMfaTransactionCacheSize {
		now := time.Now()
		// Purgar expirados primero
		for k, v := range mfaTransactionCache {
			if now.After(v.ExpiresAt) {
				delete(mfaTransactionCache, k)
			}
		}
		// Si aún supera el umbral, desalojar la primera entrada arbitraria
		if len(mfaTransactionCache) >= maxMfaTransactionCacheSize {
			for k := range mfaTransactionCache {
				delete(mfaTransactionCache, k)
				break
			}
		}
	}

	transactionID, err := generateTransactionID()
	if err != nil {
		return "", err
	}

	mfaTransactionCache[transactionID] = &MfaTransaction{
		MfaToken:       mfaToken,
		UserID:         userID,
		Username:       username,
		AppID:          appID,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
		Consumed:       false,
		SessionCookie:  sessionCookie,
		FailedAttempts: 0,
		Locked:         false,
	}

	return transactionID, nil
}

// GetMfaTransaction retrieves an MFA transaction if it exists, is not expired, and is not consumed
func GetMfaTransaction(transactionID string, sessionCookie string) (*MfaTransaction, error) {
	mfaTransactionMutex.RLock()
	defer mfaTransactionMutex.RUnlock()

	txn, exists := mfaTransactionCache[transactionID]
	if !exists {
		return nil, fmt.Errorf("transacción MFA no encontrada o expirada")
	}

	if time.Now().After(txn.ExpiresAt) {
		return nil, fmt.Errorf("transacción MFA expirada")
	}

	if txn.Consumed {
		return nil, fmt.Errorf("transacción MFA ya fue utilizada")
	}

	if txn.Locked {
		return nil, fmt.Errorf("transacción MFA bloqueada por exceso de intentos fallidos")
	}

	// Bind to session cookie for additional security
	if txn.SessionCookie != sessionCookie {
		return nil, fmt.Errorf("transacción MFA no coincide con la sesión del navegador")
	}

	return txn, nil
}

// ConsumeMfaTransaction marks a transaction as consumed (one-time use)
func ConsumeMfaTransaction(transactionID string) error {
	mfaTransactionMutex.Lock()
	defer mfaTransactionMutex.Unlock()

	txn, exists := mfaTransactionCache[transactionID]
	if !exists {
		return fmt.Errorf("transacción MFA no encontrada")
	}

	if txn.Consumed {
		return fmt.Errorf("transacción MFA ya fue consumida")
	}

	txn.Consumed = true
	return nil
}

// RecordMfaFailedAttempt increments the failed attempt counter for an MFA transaction
// using database-backed tracking to work across all instances.
// Returns an error if the transaction is now locked.
func RecordMfaFailedAttempt(transactionID string) error {
	// Also update in-memory state for consistency
	mfaTransactionMutex.Lock()
	txn, exists := mfaTransactionCache[transactionID]
	if exists {
		txn.FailedAttempts++
	}
	mfaTransactionMutex.Unlock()

	if !exists {
		return fmt.Errorf("transacción MFA no encontrada")
	}

	// Use database-backed tracking for cross-instance consistency
	if mfaAttemptRepo == nil {
		// Fallback to in-memory only if repo not initialized
		mfaTransactionMutex.Lock()
		defer mfaTransactionMutex.Unlock()
		const maxMfaAttempts = 5
		if txn.FailedAttempts >= maxMfaAttempts {
			txn.Locked = true
			return fmt.Errorf("transacción MFA bloqueada por exceso de intentos fallidos")
		}
		return nil
	}

	const maxMfaAttempts = 5
	locked, err := mfaAttemptRepo.RecordFailedAttempt(transactionID, txn.UserID, maxMfaAttempts)
	if err != nil {
		return fmt.Errorf("error registrando intento fallido: %w", err)
	}

	if locked {
		// Update in-memory state
		mfaTransactionMutex.Lock()
		if txn, exists := mfaTransactionCache[transactionID]; exists {
			txn.Locked = true
		}
		mfaTransactionMutex.Unlock()
		return fmt.Errorf("transacción MFA bloqueada por exceso de intentos fallidos")
	}

	return nil
}

// DeleteMfaTransaction removes an MFA transaction from the cache
func DeleteMfaTransaction(transactionID string) {
	mfaTransactionMutex.Lock()
	defer mfaTransactionMutex.Unlock()
	delete(mfaTransactionCache, transactionID)
}

// API MFA Token Attempt Tracking - Database-backed tracking for API MFA tokens
// that are sent directly in requests (not stored server-side like admin transactions)

// RecordApiMfaFailedAttempt increments the failed attempt counter for an API MFA token
// using database-backed tracking to work across all instances.
// The tokenKey should be a hash or unique identifier of the MFA token.
// Returns an error if the token is now locked.
func RecordApiMfaFailedAttempt(tokenKey string, userID uint) error {
	if mfaAttemptRepo == nil {
		return fmt.Errorf("MFA attempt tracking not initialized")
	}

	const maxMfaAttempts = 5
	locked, err := mfaAttemptRepo.RecordFailedAttempt(tokenKey, userID, maxMfaAttempts)
	if err != nil {
		return fmt.Errorf("error registrando intento fallido: %w", err)
	}

	if locked {
		return fmt.Errorf("token MFA bloqueado por exceso de intentos fallidos")
	}

	return nil
}

// IsApiMfaTokenLocked checks if an API MFA token is locked due to excessive failures
// using database-backed tracking to work across all instances.
func IsApiMfaTokenLocked(tokenKey string) bool {
	if mfaAttemptRepo == nil {
		return false
	}

	locked, err := mfaAttemptRepo.IsLocked(tokenKey)
	if err != nil {
		// Log error but don't block on database errors
		return false
	}

	return locked
}

// DeleteApiMfaAttemptTracker removes an API MFA attempt tracker (called on successful validation)
func DeleteApiMfaAttemptTracker(tokenKey string) {
	if mfaAttemptRepo != nil {
		_ = mfaAttemptRepo.ClearAttempts(tokenKey)
	}
}

// ConsumeApiMfaToken atomically marks an API MFA token as consumed to prevent replay attacks
// Returns an error if the token was already consumed
func ConsumeApiMfaToken(tokenKey string, userID uint) error {
	if mfaAttemptRepo == nil {
		return fmt.Errorf("MFA attempt tracking not initialized")
	}

	err := mfaAttemptRepo.MarkConsumed(tokenKey, userID)
	if err != nil {
		return fmt.Errorf("token MFA ya fue utilizado o expiró")
	}

	return nil
}

// IsApiMfaTokenConsumed checks if an API MFA token has already been consumed
func IsApiMfaTokenConsumed(tokenKey string) bool {
	if mfaAttemptRepo == nil {
		return false
	}

	consumed, err := mfaAttemptRepo.IsConsumed(tokenKey)
	if err != nil {
		// Log error but don't block on database errors
		return false
	}

	return consumed
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
