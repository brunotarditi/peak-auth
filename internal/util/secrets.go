package util

import (
	"context"
	"fmt"
	"log"
	"os"

	infisical "github.com/infisical/go-sdk"
)

// LoadSecretsFromInfisical consulta Infisical si las credenciales de Machine Identity están presentes en el entorno.
func LoadSecretsFromInfisical() error {
	clientID := os.Getenv("INFISICAL_CLIENT_ID")
	clientSecret := os.Getenv("INFISICAL_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		if IsProduction() {
			return fmt.Errorf("faltan INFISICAL_CLIENT_ID o INFISICAL_CLIENT_SECRET en producción")
		}
		return nil
	}

	siteURL := os.Getenv("INFISICAL_URL")
	if siteURL == "" {
		if IsProduction() {
			return fmt.Errorf("falta INFISICAL_URL en producción")
		}
		return nil
	}

	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	projectSlug := os.Getenv("INFISICAL_PROJECT_SLUG")
	if projectID == "" && projectSlug == "" {
		if IsProduction() {
			return fmt.Errorf("falta INFISICAL_PROJECT_ID o INFISICAL_PROJECT_SLUG en producción")
		}
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
		if IsProduction() {
			return fmt.Errorf("no se pudo autenticar con Infisical: %w", err)
		}
		log.Printf("⚠️ No se pudo autenticar con Infisical: %v. Continuando con variables locales...", err)
		return nil
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
		if IsProduction() {
			return fmt.Errorf("no se pudieron obtener secretos de Infisical: %w", err)
		}
		log.Printf("⚠️ No se pudieron obtener secretos de Infisical: %v", err)
		return nil
	}

	for _, s := range res.Secrets {
		if err := os.Setenv(s.SecretKey, s.SecretValue); err != nil {
			if IsProduction() {
				return fmt.Errorf("no se pudo inyectar el secreto %q: %w", s.SecretKey, err)
			}
			log.Printf("⚠️ No se pudo inyectar el secreto %q: %v", s.SecretKey, err)
		}
	}

	log.Printf("🔐 Infisical: %d secretos inyectados exitosamente (entorno: %s)", len(res.Secrets), envSlug)
	return nil
}
