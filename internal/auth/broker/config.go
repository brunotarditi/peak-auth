package broker

import (
	"fmt"
	"os"
	"strings"
)

// BrokerConfig contiene las credenciales y URLs para los proveedores de identidad social
type BrokerConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string
}

// LoadConfigFromEnv carga la configuración de Identity Brokering desde variables de entorno
func LoadConfigFromEnv() BrokerConfig {
	baseURL := strings.TrimRight(os.Getenv("APP_BASE_URL"), "/")
	if baseURL == "" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		host := os.Getenv("HOST")
		if host == "" {
			host = "localhost"
		}
		baseURL = fmt.Sprintf("http://%s:%s", host, port)
	}

	googleRedirect := os.Getenv("GOOGLE_REDIRECT_URL")
	if googleRedirect == "" {
		googleRedirect = fmt.Sprintf("%s/oauth/broker/google/callback", baseURL)
	}

	githubRedirect := os.Getenv("GITHUB_REDIRECT_URL")
	if githubRedirect == "" {
		githubRedirect = fmt.Sprintf("%s/oauth/broker/github/callback", baseURL)
	}

	return BrokerConfig{
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  googleRedirect,

		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURL:  githubRedirect,
	}
}

func (c BrokerConfig) IsGoogleConfigured() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != ""
}

func (c BrokerConfig) IsGitHubConfigured() bool {
	return c.GitHubClientID != "" && c.GitHubClientSecret != ""
}
