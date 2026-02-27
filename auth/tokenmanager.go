package auth

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager gestiona la generación y validación de tokens JWT.
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// CustomClaims define qué info viajará en el token
type CustomClaims struct {
	Username string `json:"username"`
	AppID    string `json:"app_id"`
	jwt.RegisteredClaims
}

// NewJWTManager crea una nueva instancia de JWTManager.
// Lee la clave privada RSA (en formato PEM) desde la variable de entorno JWT_PRIVATE_KEY.
//
// Para generar un par de claves RSA puedes usar openssl:
//  1. Generar clave privada:
//     openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
//  2. Para configurar la variable de entorno, es recomendable usar el contenido del fichero en una sola línea.
//     En Linux/macOS: export JWT_PRIVATE_KEY=$(cat private_key.pem)
func NewJWTManager() (*JWTManager, error) {
	privKeyPEM := os.Getenv("JWT_PRIVATE_KEY")
	if privKeyPEM == "" {
		// permitir especificar una ruta a un archivo PEM
		path := os.Getenv("JWT_PRIVATE_KEY_PATH")
		if path == "" {
			return nil, fmt.Errorf("la variable de entorno JWT_PRIVATE_KEY o JWT_PRIVATE_KEY_PATH no está definida")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("no se pudo leer el archivo de clave privada '%s': %w", path, err)
		}
		privKeyPEM = string(data)
	} else {
		// Si la clave fue colocada en una sola línea con '\n', convertir a saltos de línea reales
		privKeyPEM = strings.ReplaceAll(privKeyPEM, "\\n", "\n")
		// Quitar comillas envolventes si las hubiera
		privKeyPEM = strings.Trim(privKeyPEM, "\"")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("no se pudo parsear la clave privada RSA desde PEM; asegúrate de que JWT_PRIVATE_KEY o JWT_PRIVATE_KEY_PATH apunten a una clave PEM válida: %w", err)
	}

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GenerateToken crea un nuevo token JWT para un usuario y aplicación específicos.
func (m *JWTManager) GenerateToken(userID uint, username string, appID string, duration time.Duration) (string, error) {
	claims := CustomClaims{
		Username: username,
		AppID:    appID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

// VerifyToken comprueba la validez de un token y devuelve sus claims si es correcto.
func (m *JWTManager) VerifyToken(tokenString string) (*CustomClaims, error) {
	if m.publicKey == nil {
		return nil, fmt.Errorf("la clave pública no está cargada en el manager")
	}
	// 1. Instanciamos el struct antes de parsear
	claims := &CustomClaims{}

	// 2. Pasamos 'claims' (el puntero) directamente aquí
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	// 3. Si hay error de parseo (expirado, firma mal, etc.), lo devolvemos
	if err != nil {
		return nil, err
	}

	// 4. Validamos que el token sea formalmente válido
	if !token.Valid {
		return nil, fmt.Errorf("token inválido")
	}

	// Como pasamos el puntero 'claims' al inicio, si token.Valid es true,
	// 'claims' ya tiene los datos cargados. No hace falta casting.
	return claims, nil
}
