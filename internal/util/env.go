package util

import (
	"net/url"
	"os"
	"strings"
)

// IsProduction indica si la aplicación corre en entorno productivo.
// Acepta "production" y "prod" para tolerar configuraciones existentes.
func IsProduction() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	return env == "production" || env == "prod"
}

// Scheme retorna el esquema HTTP a usar según el entorno (https en producción).
func Scheme() string {
	if IsProduction() {
		return "https"
	}
	return "http"
}

// BaseURL construye la URL base pública de la aplicación.
// Prioriza APP_BASE_URL si está definida; de lo contrario la deriva de HOST/PORT.
func BaseURL() string {
	if base := strings.TrimSpace(os.Getenv("APP_BASE_URL")); base != "" {
		return strings.TrimRight(base, "/")
	}

	host := strings.TrimSpace(os.Getenv("HOST"))
	if host == "" {
		host = "localhost"
	}
	port := strings.TrimSpace(os.Getenv("PORT"))

	scheme := Scheme()
	// En producción detrás de TLS no se incluye el puerto si es el estándar.
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host
	}

	return scheme + "://" + host + ":" + port
}

// SameOriginRequest valida que el header Origin/Referer pertenezca al mismo host
// que la petición. Devuelve true solo si el origen es confiable.
func SameOriginRequest(origin, requestHost string) bool {
	if origin == "" || requestHost == "" {
		return false
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}

	// Normalizamos ambos hosts (quitamos puerto si es el default)
	originHost := normalizeHost(u.Host)
	requestHostNormalized := normalizeHost(requestHost)

	return strings.EqualFold(originHost, requestHostNormalized)
}

func normalizeHost(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		port := host[idx+1:]
		base := host[:idx]

		// Si es puerto estándar por defecto HTTP/HTTPS, lo removemos
		if port == "80" || port == "443" {
			return base
		}
	}
	return host
}
