package auth

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
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

// JWTManager gestiona la generación y validación de tokens JWT.
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// CustomClaims define qué info viajará en el token
type CustomClaims struct {
	Username string   `json:"username"`
	AppID    string   `json:"app_id"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// NewJWTManager crea una nueva instancia de JWTManager.
// Lee la clave privada RSA (en formato PEM) desde la variable de entorno JWT_PRIVATE_KEY.
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

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GenerateToken crea un nuevo token JWT para un usuario y aplicación específicos.
// El token incluye el issuer (Peak Auth) y la audiencia (app_id), de modo que cada
// aplicación pueda validar que el token fue emitido específicamente para ella.
func (m *JWTManager) GenerateToken(userID uint, username string, appID string, roles []string, duration time.Duration) (string, error) {
	claims := CustomClaims{
		Username: username,
		AppID:    appID,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    tokenIssuer(),
			Audience:  jwt.ClaimStrings{appID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-45 * time.Second)), // Permitir una pequeña ventana de clock skew
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
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
	if m.publicKey == nil {
		return nil, fmt.Errorf("la clave pública no está cargada en el manager")
	}
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
		return m.publicKey, nil
	}, opts...)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}

	return claims, nil
}

// GenerateMFAPendingToken genera un token temporal (5 minutos) que indica que el login
// con contraseña fue exitoso pero está pendiente de verificar el segundo factor.
func (m *JWTManager) GenerateMFAPendingToken(userID uint, username string, appID string) (string, error) {
	claims := CustomClaims{
		Username: username,
		AppID:    appID,
		Roles:    []string{"MFA_PENDING"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    tokenIssuer(),
			Audience:  jwt.ClaimStrings{appID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

// VerifyMFAPendingToken verifica que el token temporal de MFA sea válido.
func (m *JWTManager) VerifyMFAPendingToken(tokenString string, expectedAppID string) (*CustomClaims, error) {
	claims, err := m.verify(tokenString, expectedAppID)
	if err != nil {
		return nil, err
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "MFA_PENDING" {
		return nil, fmt.Errorf("token inválido para verificación MFA")
	}
	return claims, nil
}
