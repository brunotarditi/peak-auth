package util

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	turnstileVerifyURL  = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	turnstileHTTPClient = &http.Client{Timeout: 5 * time.Second}
)

// TurnstileSiteKey retorna la clave pública del widget Turnstile configurada en el entorno.
func TurnstileSiteKey() string {
	return strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY"))
}

// TurnstileSecretKey retorna la clave secreta de Turnstile configurada en el entorno.
func TurnstileSecretKey() string {
	return strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
}

// IsTurnstileEnabled indica si Cloudflare Turnstile está configurado y activo.
func IsTurnstileEnabled() bool {
	return TurnstileSiteKey() != "" && TurnstileSecretKey() != ""
}

type turnstileVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// VerifyTurnstileToken valida el token cf-turnstile-response contra la API de Cloudflare.
// Si Turnstile no está habilitado (faltan claves en el entorno), retorna true sin bloquear.
func VerifyTurnstileToken(token, remoteIP string) (bool, error) {
	if !IsTurnstileEnabled() {
		return true, nil
	}

	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return false, nil
	}

	form := url.Values{}
	form.Set("secret", TurnstileSecretKey())
	form.Set("response", cleanToken)
	if ip := strings.TrimSpace(remoteIP); ip != "" {
		form.Set("remoteip", ip)
	}

	resp, err := turnstileHTTPClient.PostForm(turnstileVerifyURL, form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Success, nil
}
