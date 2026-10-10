package peakauth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type refreshCall struct {
	wg  sync.WaitGroup
	val *TokenResponse
	err error
}

// Client gestiona la interacción con Peak Auth, el cacheo de JWKS y la validación de tokens.
type Client struct {
	config Config

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time

	refreshMu    sync.Mutex
	refreshCalls map[string]*refreshCall
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// validateURL valida estrictamente que la URL sea absoluta, bien formada, sin credenciales ni fragments,
// y con HTTPS obligatorio para cualquier host no loopback.
func validateURL(rawURL string, isIssuer bool, insecureAllowHTTP bool) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("URL no puede estar vacía")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("error parseando URL %q: %w", rawURL, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("URL %q debe ser absoluta y contener un host válido", rawURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL %q no puede contener credenciales de autenticación", rawURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("URL %q no puede contener fragmentos (#)", rawURL)
	}
	if isIssuer && u.RawQuery != "" {
		return nil, fmt.Errorf("IssuerURL %q no puede contener query parameters (?)", rawURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("esquema de URL no válido (%q): debe ser https o http", u.Scheme)
	}
	if u.Scheme == "http" {
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("URL insegura (%s): HTTPS es obligatorio para hosts remotos; HTTP no está permitido para hosts no loopback bajo ninguna circunstancia", rawURL)
		}
		if !insecureAllowHTTP {
			return nil, fmt.Errorf("URL loopback con HTTP (%s) requiere InsecureAllowHTTP = true para desarrollo local controlado", rawURL)
		}
	}
	return u, nil
}

// Log emite un mensaje formateado al registrador interno si está configurado.
func (c *Client) Log(format string, args ...any) {
	if c.config.Logger != nil {
		c.config.Logger(format, args...)
	}
}

// New crea e inicializa un nuevo Client de Peak Auth con validación estricta de transporte.
func New(cfg Config) (*Client, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("peakauth: IssuerURL es requerido")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("peakauth: ClientID es requerido")
	}

	u, err := validateURL(cfg.IssuerURL, true, cfg.InsecureAllowHTTP)
	if err != nil {
		return nil, fmt.Errorf("peakauth: %w", err)
	}

	cfg.IssuerURL = strings.TrimRight(u.String(), "/")
	if cfg.ExpectedIssuer == "" {
		cfg.ExpectedIssuer = "peak-auth"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.ClockTolerance <= 0 {
		cfg.ClockTolerance = 45 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		config:       cfg,
		keys:         make(map[string]*rsa.PublicKey),
		refreshCalls: make(map[string]*refreshCall),
	}, nil
}

// GetAuthorizationURL genera la URL para redirigir al usuario al login de Peak Auth.
// Para clientes públicos (sin ClientSecret), codeChallenge es obligatorio.
func (c *Client) GetAuthorizationURL(state string, codeChallenge string, extraParams ...map[string]string) (string, error) {
	redirectURI := c.config.RedirectURI
	if redirectURI == "" {
		return "", fmt.Errorf("peakauth: RedirectURI es requerida para construir la URL de autorización")
	}

	if c.config.ClientSecret == "" && strings.TrimSpace(codeChallenge) == "" {
		return "", fmt.Errorf("peakauth: code_challenge es obligatorio para clientes públicos (sin client_secret)")
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

// GetLogoutURL genera la URL para redirigir al usuario al endpoint de Federated Logout (/oauth/logout).
// Inyecta automáticamente el ClientID configurado y opcionalmente la post_logout_redirect_uri.
// Si postLogoutRedirectURI es vacía, intentará usar la RedirectURI del cliente si está configurada.
func (c *Client) GetLogoutURL(postLogoutRedirectURI string, extraParams ...map[string]string) (string, error) {
	u, err := url.Parse(c.config.IssuerURL + "/oauth/logout")
	if err != nil {
		return "", fmt.Errorf("error parseando IssuerURL: %w", err)
	}

	targetRedirect := postLogoutRedirectURI
	if targetRedirect == "" {
		targetRedirect = c.config.RedirectURI
	}

	q := u.Query()
	q.Set("client_id", c.config.ClientID)
	if targetRedirect != "" {
		q.Set("post_logout_redirect_uri", targetRedirect)
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
// Para clientes públicos (sin ClientSecret), codeVerifier es obligatorio.
func (c *Client) ExchangeCode(ctx context.Context, code string, codeVerifier string, redirectURI ...string) (*TokenResponse, error) {
	if c.config.ClientSecret == "" && strings.TrimSpace(codeVerifier) == "" {
		return nil, fmt.Errorf("peakauth: code_verifier es obligatorio para clientes públicos (sin client_secret)")
	}

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
// Implementa deduplicación de peticiones concurrentes (single-flight) sobre el mismo refresh token
// para prevenir que peticiones paralelas invaliden tokens rotativos.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("peakauth: refreshToken no puede estar vacío")
	}

	c.refreshMu.Lock()
	if call, exists := c.refreshCalls[refreshToken]; exists {
		c.refreshMu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}

	call := new(refreshCall)
	call.wg.Add(1)
	c.refreshCalls[refreshToken] = call
	c.refreshMu.Unlock()

	defer func() {
		c.refreshMu.Lock()
		delete(c.refreshCalls, refreshToken)
		c.refreshMu.Unlock()
		call.wg.Done()
	}()

	call.val, call.err = c.executeRefreshToken(ctx, refreshToken)
	return call.val, call.err
}

func (c *Client) executeRefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
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
	return c.VerifyTokenWithContext(context.Background(), tokenString)
}

// VerifyTokenWithContext valida el token permitiendo pasar un context.Context para cancelación o timeout.
// Valida obligatoriamente expiración (exp), emisor (iss), audiencia (aud) y fecha de emisión (iat).
func (c *Client) VerifyTokenWithContext(ctx context.Context, tokenString string) (*Claims, error) {
	claims := &Claims{}

	leeway := c.config.ClockTolerance
	if leeway <= 0 {
		leeway = 45 * time.Second
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(leeway),
		jwt.WithIssuer(c.config.ExpectedIssuer),
		jwt.WithAudience(c.config.ClientID),
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		alg, _ := t.Header["alg"].(string)
		if alg != "RS256" {
			return nil, fmt.Errorf("método de firma no permitido (%s): solo se acepta RS256", alg)
		}

		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("método de firma no permitido: %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		pubKey, err := c.getKey(ctx, kid)
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

	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("token inválido: claim 'exp' es obligatorio")
	}
	if claims.IssuedAt != nil && claims.IssuedAt.Time.After(time.Now().Add(leeway)) {
		return nil, fmt.Errorf("token inválido: emitido en el futuro (iat)")
	}

	return claims, nil
}

// GetOpenIDConfiguration obtiene los metadatos del servidor desde /.well-known/openid-configuration
// y valida que issuer, endpoints y jwks_uri pertenezcan al mismo origen seguro configurado.
func (c *Client) GetOpenIDConfiguration(ctx context.Context) (*OpenIDConfiguration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.IssuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error solicitando OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openid-configuration devolvió status: %d", resp.StatusCode)
	}

	var cfg OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	baseIssuerURL, err := url.Parse(c.config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("error parseando IssuerURL base: %w", err)
	}

	discIssuerURL, err := validateURL(cfg.Issuer, true, c.config.InsecureAllowHTTP)
	if err != nil {
		return nil, fmt.Errorf("openid-configuration: issuer descubierto inválido: %w", err)
	}

	if discIssuerURL.Scheme != baseIssuerURL.Scheme {
		return nil, fmt.Errorf("openid-configuration: scheme del issuer (%s) no coincide con el configurado (%s)", discIssuerURL.Scheme, baseIssuerURL.Scheme)
	}
	if !strings.EqualFold(discIssuerURL.Hostname(), baseIssuerURL.Hostname()) {
		return nil, fmt.Errorf("openid-configuration: host del issuer (%s) no coincide con el emisor configurado (%s)", discIssuerURL.Hostname(), baseIssuerURL.Hostname())
	}
	if discIssuerURL.Port() != baseIssuerURL.Port() {
		return nil, fmt.Errorf("openid-configuration: puerto del issuer (%s) no coincide con el configurado (%s)", discIssuerURL.Port(), baseIssuerURL.Port())
	}
	normDiscPath := strings.TrimRight(discIssuerURL.Path, "/")
	normBasePath := strings.TrimRight(baseIssuerURL.Path, "/")
	if normDiscPath != normBasePath {
		return nil, fmt.Errorf("openid-configuration: path del issuer (%s) no coincide con el configurado (%s)", normDiscPath, normBasePath)
	}

	endpoints := map[string]string{
		"authorization_endpoint": cfg.AuthorizationEndpoint,
		"token_endpoint":         cfg.TokenEndpoint,
		"jwks_uri":               cfg.JwksURI,
	}
	for epName, epVal := range endpoints {
		if strings.TrimSpace(epVal) == "" {
			return nil, fmt.Errorf("openid-configuration: %s es obligatorio y no puede estar vacío", epName)
		}
		epURL, err := validateURL(epVal, false, c.config.InsecureAllowHTTP)
		if err != nil {
			return nil, fmt.Errorf("openid-configuration: %s inválido: %w", epName, err)
		}
		if epURL.Scheme != baseIssuerURL.Scheme {
			return nil, fmt.Errorf("openid-configuration: scheme de %s (%s) no coincide con el emisor (%s)", epName, epURL.Scheme, baseIssuerURL.Scheme)
		}
		if !strings.EqualFold(epURL.Hostname(), baseIssuerURL.Hostname()) {
			return nil, fmt.Errorf("openid-configuration: hostname de %s (%s) no coincide con el emisor (%s)", epName, epURL.Hostname(), baseIssuerURL.Hostname())
		}
		if epURL.Port() != baseIssuerURL.Port() {
			return nil, fmt.Errorf("openid-configuration: puerto de %s (%s) no coincide con el emisor (%s)", epName, epURL.Port(), baseIssuerURL.Port())
		}
	}

	return &cfg, nil
}

// getKey busca la clave pública en el cache en memoria; si no existe o expiró el TTL, recarga el JWKS con el contexto provisto.
func (c *Client) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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

	if err := c.fetchJWKSLocked(ctx); err != nil {
		return nil, err
	}

	if key, exists := c.keys[kid]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("clave pública con kid %q no encontrada en JWKS", kid)
}

// fetchJWKSLocked descarga y valida estrictamente las claves RSA desde /.well-known/jwks.json utilizando el contexto provisto.
// Debe llamarse manteniendo el lock de escritura c.mu.
func (c *Client) fetchJWKSLocked(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.IssuerURL+"/.well-known/jwks.json", nil)
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
		kid := strings.TrimSpace(k.Kid)
		if kid == "" {
			c.Log("rechazando clave JWKS sin kid")
			continue
		}
		if k.Kty != "RSA" {
			c.Log("rechazando clave JWKS %q: kty %q no es RSA", kid, k.Kty)
			continue
		}
		if k.Alg != "RS256" {
			c.Log("rechazando clave JWKS %q: alg %q inválido o ausente (se exige RS256)", kid, k.Alg)
			continue
		}
		if k.Use != "sig" {
			c.Log("rechazando clave JWKS %q: use %q inválido o ausente (se exige sig)", kid, k.Use)
			continue
		}
		pubKey, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			c.Log("rechazando clave JWKS %q: %v", kid, err)
			continue
		}
		newKeys[kid] = pubKey
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("no se encontraron claves RSA válidas en el JWKS")
	}

	c.keys = newKeys
	c.lastFetch = time.Now()
	return nil
}

// parseRSAPublicKey construye un *rsa.PublicKey a partir de n y e en Base64RawURL con validación estricta.
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(nStr) == "" || strings.TrimSpace(eStr) == "" {
		return nil, fmt.Errorf("módulo n y exponente e son requeridos")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("error decodificando n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("error decodificando e: %w", err)
	}

	if len(eBytes) == 0 {
		return nil, fmt.Errorf("exponente e vacío")
	}
	if len(eBytes) > 4 {
		return nil, fmt.Errorf("exponente e demasiado grande (más de 4 bytes / overflow)")
	}

	var e int64
	for _, b := range eBytes {
		e = (e << 8) | int64(b)
	}

	if e <= 0 || e > int64(math.MaxInt32) {
		return nil, fmt.Errorf("exponente e fuera de rango positivo de 32 bits: %d", e)
	}
	if e < 3 {
		return nil, fmt.Errorf("exponente e debe ser >= 3 (recibido %d)", e)
	}
	if e%2 == 0 {
		return nil, fmt.Errorf("exponente e debe ser impar (recibido %d)", e)
	}

	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("tamaño de clave RSA inferior a 2048 bits (%d bits)", n.BitLen())
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}

// IntrospectToken realiza una validación online del token contra el servidor de autorización.
// Este método consulta el endpoint /api/v1/introspect para verificar el estado actual del token,
// incluyendo si ha sido revocado. Requiere que el cliente tenga configurado ClientSecret.
func (c *Client) IntrospectToken(ctx context.Context, tokenString string) (*IntrospectionResponse, error) {
	if c.config.ClientSecret == "" {
		return nil, fmt.Errorf("peakauth: ClientSecret es requerido para introspección")
	}

	payload, err := json.Marshal(map[string]string{
		"token": tokenString,
	})
	if err != nil {
		return nil, fmt.Errorf("error codificando payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.IssuerURL+"/api/v1/introspect", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("error creando request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-App-Id", c.config.ClientID)
	req.Header.Set("X-App-Secret", c.config.ClientSecret)

	resp, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error llamando a /api/v1/introspect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspección falló con status: %d", resp.StatusCode)
	}

	var introspectResp IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		return nil, fmt.Errorf("error decodificando respuesta de introspección: %w", err)
	}

	return &introspectResp, nil
}

