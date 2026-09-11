package peakauth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config define las opciones para inicializar el cliente Peak Auth.
type Config struct {
	// IssuerURL es la URL base del servidor Peak Auth (ej. "https://auth.tuempresa.com" o "http://localhost:8080").
	IssuerURL string

	// ClientID es el identificador único de la aplicación registrado en Peak Auth.
	ClientID string

	// ClientSecret es el secret de la aplicación (opcional para clientes públicos con PKCE).
	ClientSecret string

	// RedirectURI por defecto para los flujos OAuth.
	RedirectURI string

	// ExpectedIssuer es el issuer esperado en el JWT. Por defecto: "peak-auth".
	ExpectedIssuer string

	// CacheTTL es el tiempo de cacheo para las claves JWKS en memoria. Por defecto: 1 hora.
	CacheTTL time.Duration

	// HTTPClient personalizado para peticiones salientes (opcional).
	HTTPClient *http.Client
}

// Claims representa la información decodificada de un Access Token de Peak Auth.
type Claims struct {
	Username    string   `json:"username"`
	AppID       string   `json:"app_id"`
	Roles       []string `json:"roles"`
	MfaVerified bool     `json:"mfa_verified"`
	TokenType   string   `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenResponse representa la respuesta de /oauth/token y /api/v1/refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// PKCEPair contiene el par criptográfico code_verifier y code_challenge.
type PKCEPair struct {
	CodeVerifier  string
	CodeChallenge string
}

// OpenIDConfiguration representa la respuesta del endpoint /.well-known/openid-configuration.
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// jwk representa una clave individual dentro del JSON Web Key Set.
type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse representa el JSON devuelto por /.well-known/jwks.json.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}
