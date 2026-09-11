package peakauth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client gestiona la interacción con Peak Auth, el cacheo de JWKS y la validación de tokens.
type Client struct {
	config Config

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// New crea e inicializa un nuevo Client de Peak Auth.
func New(cfg Config) (*Client, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("peakauth: IssuerURL es requerido")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("peakauth: ClientID es requerido")
	}

	cfg.IssuerURL = strings.TrimRight(cfg.IssuerURL, "/")
	if cfg.ExpectedIssuer == "" {
		cfg.ExpectedIssuer = "peak-auth"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		config: cfg,
		keys:   make(map[string]*rsa.PublicKey),
	}, nil
}

// GetAuthorizationURL genera la URL para redirigir al usuario al login de Peak Auth.
func (c *Client) GetAuthorizationURL(state string, codeChallenge string, extraParams ...map[string]string) (string, error) {
	redirectURI := c.config.RedirectURI
	if redirectURI == "" {
		return "", fmt.Errorf("peakauth: RedirectURI es requerida para construir la URL de autorización")
	}

	u, err := url.Parse(c.config.IssuerURL + "/oauth/authorize")
	if err != nil {
		return "", fmt.Errorf("error parseando IssuerURL: %w", err)
	}

	q := u.Query()
	q.Set("client_id", c.config.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")

	if state != "" {
		q.Set("state", state)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}

	for _, m := range extraParams {
		for k, v := range m {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode intercambia un código de autorización por tokens en /oauth/token.
func (c *Client) ExchangeCode(ctx context.Context, code string, codeVerifier string, redirectURI ...string) (*TokenResponse, error) {
	targetRedirect := c.config.RedirectURI
	if len(redirectURI) > 0 && redirectURI[0] != "" {
		targetRedirect = redirectURI[0]
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.config.ClientID)
	data.Set("code", code)
	data.Set("redirect_uri", targetRedirect)

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.IssuerURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creando request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error llamando a /oauth/token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		desc := errBody.Description
		if desc == "" {
			desc = errBody.Error
		}
		return nil, fmt.Errorf("token exchange falló (%d): %s", resp.StatusCode, desc)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("error decodificando respuesta de token: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken renueva un token de acceso a través de /api/v1/refresh.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	payload, err := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.IssuerURL+"/api/v1/refresh", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh falló con status: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("error parseando refresh response: %w", err)
	}

	return &tokenResp, nil
}

// VerifyToken valida la firma RSA del JWT utilizando el JWKS en memoria,
// así como su expiración, emisor (iss) y audiencia (aud).
func (c *Client) VerifyToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(45 * time.Second),
		jwt.WithIssuer(c.config.ExpectedIssuer),
		jwt.WithAudience(c.config.ClientID),
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de firma no permitido: %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		pubKey, err := c.getKey(kid)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	}, opts...)

	if err != nil {
		return nil, fmt.Errorf("token inválido: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token no válido")
	}

	return claims, nil
}

// GetOpenIDConfiguration obtiene los metadatos del servidor desde /.well-known/openid-configuration.
func (c *Client) GetOpenIDConfiguration(ctx context.Context) (*OpenIDConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.IssuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openid-configuration falló con HTTP %d", resp.StatusCode)
	}

	var cfg OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// getKey busca la clave pública en el cache en memoria; si no existe o expiró el TTL, recarga el JWKS.
func (c *Client) getKey(kid string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, fmt.Errorf("el header del token no incluye 'kid' válido")
	}

	c.mu.RLock()
	if time.Since(c.lastFetch) < c.config.CacheTTL {
		if key, exists := c.keys[kid]; exists {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Actualizar cache con Lock de escritura
	c.mu.Lock()
	defer c.mu.Unlock()

	// Doble comprobación
	if time.Since(c.lastFetch) < c.config.CacheTTL {
		if key, exists := c.keys[kid]; exists {
			return key, nil
		}
	}

	if err := c.fetchJWKSLocked(); err != nil {
		return nil, err
	}

	if key, exists := c.keys[kid]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("clave pública con kid %q no encontrada en JWKS", kid)
}

// fetchJWKSLocked descarga y parsea las claves RSA desde /.well-known/jwks.json.
// Debe llamarse manteniendo el lock de escritura c.mu.
func (c *Client) fetchJWKSLocked() error {
	req, err := http.NewRequest(http.MethodGet, c.config.IssuerURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return err
	}

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("error solicitando JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint devolvió status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("error decodificando JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pubKey
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("no se encontraron claves RSA válidas en el JWKS")
	}

	c.keys = newKeys
	c.lastFetch = time.Now()
	return nil
}

// parseRSAPublicKey construye un *rsa.PublicKey a partir de n y e en Base64RawURL.
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("error decodificando n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("error decodificando e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
