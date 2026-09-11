package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenIssuer identifica al emisor (issuer) de los tokens. Puede sobreescribirse
// con la variable de entorno JWT_ISSUER.
func tokenIssuer() string {
	if iss := strings.TrimSpace(os.Getenv("JWT_ISSUER")); iss != "" {
		return iss
	}
	return "peak-auth"
}

// defaultKeyID identifica la clave activa utilizada para la firma de JWTs y en el JWKS.
const defaultKeyID = "peak-auth-key-1"

// JWTManager gestiona la generación y validación de tokens JWT con soporte para rotación multi-clave y grace period.
type JWTManager struct {
	mu           sync.RWMutex
	activeKid    string
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	previousKeys map[string]*rsa.PublicKey
}

// CustomClaims define qué info viajará en el token
type CustomClaims struct {
	Username    string   `json:"username"`
	AppID       string   `json:"app_id"`
	Roles       []string `json:"roles"`
	MfaVerified bool     `json:"mfa_verified"`
	TokenType   string   `json:"token_type"`
	jwt.RegisteredClaims
}

// NewJWTManager crea una nueva instancia de JWTManager.
// Lee la clave privada RSA (en formato PEM) desde la variable de entorno JWT_PRIVATE_KEY.
// Opcionalmente lee JWT_KEY_ID (por defecto peak-auth-key-1) y JWT_PREVIOUS_KEYS (JSON de claves en período de gracia).
func NewJWTManager() (*JWTManager, error) {
	privKeyPEM := os.Getenv("JWT_PRIVATE_KEY")
	if privKeyPEM == "" {
		return nil, fmt.Errorf("la variable de entorno JWT_PRIVATE_KEY no está definida")
	}
	privKeyPEM = strings.ReplaceAll(privKeyPEM, "\\n", "\n")
	privKeyPEM = strings.Trim(privKeyPEM, "\"")

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("no se pudo parsear la clave privada RSA desde PEM; asegúrate de que JWT_PRIVATE_KEY apunten a una clave PEM válida: %w", err)
	}

	activeKid := strings.TrimSpace(os.Getenv("JWT_KEY_ID"))
	if activeKid == "" {
		activeKid = defaultKeyID
	}

	mgr := &JWTManager{
		activeKid:    activeKid,
		privateKey:   privateKey,
		publicKey:    &privateKey.PublicKey,
		previousKeys: make(map[string]*rsa.PublicKey),
	}

	// Cargar claves públicas anteriores para período de gracia si están configuradas
	if prevKeysJSON := strings.TrimSpace(os.Getenv("JWT_PREVIOUS_KEYS")); prevKeysJSON != "" {
		var entries []struct {
			Kid       string `json:"kid"`
			PublicKey string `json:"public_key"`
		}
		if err := json.Unmarshal([]byte(prevKeysJSON), &entries); err != nil {
			return nil, fmt.Errorf("error al parsear JWT_PREVIOUS_KEYS (debe ser un JSON array válido): %w", err)
		}
		for _, entry := range entries {
			if entry.Kid != "" && entry.PublicKey != "" {
				if err := mgr.AddPreviousPublicKeyPEM(entry.Kid, []byte(entry.PublicKey)); err != nil {
					return nil, fmt.Errorf("error cargando clave previa (%s) desde JWT_PREVIOUS_KEYS: %w", entry.Kid, err)
				}
			}
		}
	}

	return mgr, nil
}

// ActiveKeyID devuelve el identificador de la clave activa actual.
func (m *JWTManager) ActiveKeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeKid
}

// AddPreviousPublicKey registra una clave pública anterior válida durante el período de gracia.
func (m *JWTManager) AddPreviousPublicKey(kid string, pubKey *rsa.PublicKey) {
	if kid == "" || pubKey == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.previousKeys[kid] = pubKey
}

// RemovePreviousPublicKey retira una clave del período de gracia una vez expirada la ventana.
func (m *JWTManager) RemovePreviousPublicKey(kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.previousKeys, kid)
}

// AddPreviousPublicKeyPEM registra una clave pública anterior parseándola desde formato PEM.
func (m *JWTManager) AddPreviousPublicKeyPEM(kid string, pemBytes []byte) error {
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("error parseando clave pública RSA previa (%s): %w", kid, err)
	}
	m.AddPreviousPublicKey(kid, pubKey)
	return nil
}

// SetActiveKey actualiza la clave privada y pública activa (rotación en caliente),
// permitiendo opcionalmente mantener la clave anterior en previousKeys para el período de gracia.
func (m *JWTManager) SetActiveKey(newKid string, newPrivKey *rsa.PrivateKey, keepOldAsPrevious bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if keepOldAsPrevious && m.activeKid != "" && m.publicKey != nil {
		m.previousKeys[m.activeKid] = m.publicKey
	}

	m.activeKid = newKid
	m.privateKey = newPrivKey
	m.publicKey = &newPrivKey.PublicKey
}

// GenerateToken crea un nuevo token JWT para un usuario y aplicación específicos.
// El token incluye el issuer (Peak Auth) y la audiencia (app_id), de modo que cada
// aplicación pueda validar que el token fue emitido específicamente para ella.
func (m *JWTManager) GenerateToken(userID uint, username string, appID string, roles []string, duration time.Duration, mfaVerified bool) (string, error) {
	claims := CustomClaims{
		Username:    username,
		AppID:       appID,
		Roles:       roles,
		MfaVerified: mfaVerified,
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    tokenIssuer(),
			Audience:  jwt.ClaimStrings{appID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-45 * time.Second)), // Permitir una pequeña ventana de clock skew
		},
	}

	m.mu.RLock()
	activeKid := m.activeKid
	privKey := m.privateKey
	m.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKid
	return token.SignedString(privKey)
}

// VerifyToken comprueba la validez de un token (firma, expiración e issuer) y
// devuelve sus claims si es correcto.
func (m *JWTManager) VerifyToken(tokenString string) (*CustomClaims, error) {
	return m.verify(tokenString, "")
}

// VerifyTokenForApp valida además que la audiencia del token coincida con la app
// indicada (defensa contra el uso cruzado de tokens entre aplicaciones).
func (m *JWTManager) VerifyTokenForApp(tokenString string, expectedAppID string) (*CustomClaims, error) {
	return m.verify(tokenString, expectedAppID)
}

func (m *JWTManager) verify(tokenString string, expectedAudience string) (*CustomClaims, error) {
	claims := &CustomClaims{}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(30 * time.Second),
		jwt.WithIssuer(tokenIssuer()),
	}
	if expectedAudience != "" {
		opts = append(opts, jwt.WithAudience(expectedAudience))
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}

		kid, _ := token.Header["kid"].(string)
		pubKey, err := m.resolvePublicKey(kid)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	}, opts...)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}

	return claims, nil
}

// resolvePublicKey busca la clave pública correspondiente al kid:
// primero revisa la clave activa y luego las claves en período de gracia.
func (m *JWTManager) resolvePublicKey(kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Si no trae kid (compatibilidad con tokens anteriores) o coincide con la clave activa
	if kid == "" || kid == m.activeKid {
		if m.publicKey == nil {
			return nil, fmt.Errorf("la clave pública activa no está cargada en el manager")
		}
		return m.publicKey, nil
	}

	// Buscar en claves del período de gracia
	if prevKey, exists := m.previousKeys[kid]; exists && prevKey != nil {
		return prevKey, nil
	}

	return nil, fmt.Errorf("clave pública con kid %q no encontrada en Peak Auth", kid)
}

// GenerateMFAPendingToken genera un token temporal (5 minutos) que indica que el login
// con contraseña fue exitoso pero está pendiente de verificar el segundo factor.
// No contiene roles de aplicación ya que el login no ha finalizado.
func (m *JWTManager) GenerateMFAPendingToken(userID uint, username string, appID string) (string, error) {
	claims := CustomClaims{
		Username:    username,
		AppID:       appID,
		Roles:       []string{},
		MfaVerified: false,
		TokenType:   "mfa_pending",
	}
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   fmt.Sprintf("%d", userID),
		Issuer:    tokenIssuer(),
		Audience:  jwt.ClaimStrings{appID},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	m.mu.RLock()
	activeKid := m.activeKid
	privKey := m.privateKey
	m.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKid
	return token.SignedString(privKey)
}

// VerifyMFAPendingToken verifica que el token temporal de MFA sea válido y de tipo 'mfa_pending'.
func (m *JWTManager) VerifyMFAPendingToken(tokenString string, expectedAppID string) (*CustomClaims, error) {
	claims, err := m.verify(tokenString, expectedAppID)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "mfa_pending" || claims.MfaVerified {
		return nil, fmt.Errorf("token inválido para verificación MFA")
	}
	return claims, nil
}

// GetJWKS devuelve las claves públicas válidas (activa + anteriores) en formato JSON Web Key Set (RFC 7517).
func (m *JWTManager) GetJWKS() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []map[string]interface{}

	if m.publicKey != nil {
		keys = append(keys, m.formatJWK(m.activeKid, m.publicKey))
	}

	for kid, prevKey := range m.previousKeys {
		if prevKey != nil {
			keys = append(keys, m.formatJWK(kid, prevKey))
		}
	}

	return map[string]interface{}{
		"keys": keys,
	}
}

func (m *JWTManager) formatJWK(kid string, pubKey *rsa.PublicKey) map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

	return map[string]interface{}{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   n,
		"e":   e,
	}
}
