package util

import (
	"context"
	"log"
	"os"

	infisical "github.com/infisical/go-sdk"
)

// LoadSecretsFromInfisical consulta Infisical si las credenciales de Machine Identity están presentes en el entorno.
func LoadSecretsFromInfisical() {
	clientID := os.Getenv("INFISICAL_CLIENT_ID")
	clientSecret := os.Getenv("INFISICAL_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return
	}

	siteURL := os.Getenv("INFISICAL_URL")
	if siteURL == "" {
		return
	}

	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	projectSlug := os.Getenv("INFISICAL_PROJECT_SLUG")
	if projectID == "" && projectSlug == "" {
		projectSlug = "peak-auth"
	}

	envSlug := os.Getenv("INFISICAL_ENV")
	if envSlug == "" {
		if IsProduction() {
			envSlug = "prod"
		} else {
			envSlug = "dev"
		}
	}

	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: siteURL,
	})

	_, err := client.Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		log.Printf("⚠️ No se pudo autenticar con Infisical: %v. Continuando con variables locales...", err)
		return
	}

	res, err := client.Secrets().ListSecrets(infisical.ListSecretsOptions{
		ProjectID:              projectID,
		ProjectSlug:            projectSlug,
		Environment:            envSlug,
		SecretPath:             "/",
		Recursive:              true,
		ExpandSecretReferences: true,
	})
	if err != nil {
		log.Printf("⚠️ No se pudieron obtener secretos de Infisical: %v", err)
		return
	}

	for _, s := range res.Secrets {
		os.Setenv(s.SecretKey, s.SecretValue)
	}

	log.Printf("🔐 Infisical: %d secretos inyectados exitosamente (entorno: %s)", len(res.Secrets), envSlug)
}
