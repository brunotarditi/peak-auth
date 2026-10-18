package service

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"peak-auth/internal/util"

	"github.com/resend/resend-go/v2"
)

// EmailProvider es la interfaz para enviar correos
type EmailProvider interface {
	Send(subject, toEmail, html string) error
}

// ResendProvider usa la API de Resend (Producción)
type ResendProvider struct {
	ApiKey string
	From   string
	client *resend.Client
}

// NewResendProvider crea un proveedor de Resend con un cliente HTTP afinado (Happy Eyeballs y timeout controlado)
func NewResendProvider(apiKey, from string) *ResendProvider {
	customHTTPClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:       5 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 200 * time.Millisecond, // Si IPv6 se cuelga en el ISP, salta de inmediato a IPv4
			}).DialContext,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	return &ResendProvider{
		ApiKey: apiKey,
		From:   from,
		client: resend.NewCustomClient(customHTTPClient, apiKey),
	}
}

// ConsoleProvider solo imprime en consola (Desarrollo local)
type ConsoleProvider struct{}

// EmailService maneja la lógica de correos usando un proveedor inyectado
type EmailService struct {
	Provider EmailProvider
}

func NewEmailService() *EmailService {
	apiKey := os.Getenv("RESEND_API_KEY")
	providerType := os.Getenv("EMAIL_PROVIDER") // "RESEND" o "CONSOLE"
	from := os.Getenv("EMAIL_FROM")
	if from == "" {
		from = "Peak Auth <no-reply@brunotarditi.com>"
	}

	var provider EmailProvider
	if providerType == "RESEND" && apiKey != "" {
		provider = NewResendProvider(apiKey, from)
		log.Println("📧 Email Service initialized with RESEND provider")
	} else {
		// Fail closed in production: ConsoleProvider logs sensitive tokens
		if util.IsProduction() {
			log.Fatal("🚨 FATAL: EMAIL_PROVIDER must be RESEND with valid RESEND_API_KEY in production. " +
				"ConsoleProvider logs bearer tokens (password reset, verification) to application logs, " +
				"allowing credential theft by log readers. Set EMAIL_PROVIDER=RESEND and RESEND_API_KEY " +
				"or set ENV to development/test for local work.")
		}
		provider = &ConsoleProvider{}
		log.Println("📧 Email Service initialized with CONSOLE (Mock) provider")
	}

	return &EmailService{Provider: provider}
}

func (p *ResendProvider) Send(subject, toEmail, html string) error {
	client := p.client
	if client == nil {
		client = resend.NewClient(p.ApiKey)
	}
	params := &resend.SendEmailRequest{
		From:    p.From,
		To:      []string{toEmail},
		Subject: subject,
		Html:    html,
	}
	_, err := client.Emails.Send(params)
	return err
}

func (p *ConsoleProvider) Send(subject, toEmail, html string) error {
	divider := "================================================================"
	log.Printf("\n%s\n📧 MOCK EMAIL SENT (LOCAL DEV)\nTo: %s\nSubject: %s\n\n%s\n%s",
		divider, toEmail, subject, html, divider)
	return nil
}

func getEmailLogoURL(baseURL string) string {
	if logoEnv := strings.TrimSpace(os.Getenv("EMAIL_LOGO_URL")); logoEnv != "" {
		return logoEnv
	}
	return fmt.Sprintf("%s/static/img/logo.png", baseURL)
}

func (s *EmailService) SendVerificationEmail(toEmail string, token string, appName string) error {
	if appName == "" {
		appName = "Peak Auth"
	}

	baseURL := util.BaseURL()
	link := fmt.Sprintf("%s/verify?token=%s", baseURL, url.QueryEscape(token))
	subject := fmt.Sprintf("Activa tu cuenta en %s", appName)

	logoURL := getEmailLogoURL(baseURL)
	html, err := util.RenderVerificationEmail("web/templates/emails/verify.html", map[string]string{
		"Link":    link,
		"AppName": appName,
		"LogoURL": logoURL,
	})
	if err != nil {
		return fmt.Errorf("error renderizando email: %v", err)
	}

	return s.Provider.Send(subject, toEmail, html)
}

func (s *EmailService) SendPasswordResetEmail(toEmail string, token string) error {
	baseURL := util.BaseURL()
	link := fmt.Sprintf("%s/reset-password?token=%s", baseURL, url.QueryEscape(token))
	subject := "Restablece tu contraseña - Peak Auth"

	logoURL := getEmailLogoURL(baseURL)
	html, err := util.RenderVerificationEmail("web/templates/emails/reset.html", map[string]string{
		"Link":    link,
		"LogoURL": logoURL,
	})
	if err != nil {
		return fmt.Errorf("error renderizando email: %v", err)
	}

	return s.Provider.Send(subject, toEmail, html)
}

func (s *EmailService) SendActivationEmail(toEmail string, token string, appName string) error {
	baseURL := util.BaseURL()
	link := fmt.Sprintf("%s/reset-password?token=%s", baseURL, url.QueryEscape(token))
	subject := fmt.Sprintf("Bienvenido a %s - Activa tu cuenta", appName)

	logoURL := getEmailLogoURL(baseURL)
	html, err := util.RenderVerificationEmail("web/templates/emails/reset.html", map[string]string{
		"Link":    link,
		"LogoURL": logoURL,
		"Title":   "Activa tu Cuenta",
		"Message": fmt.Sprintf("Has sido invitado a colaborar en %s. Para comenzar, por favor establece tu contraseña de acceso.", appName),
		"Action":  "Establecer Contraseña",
	})
	if err != nil {
		return fmt.Errorf("error renderizando email: %v", err)
	}

	return s.Provider.Send(subject, toEmail, html)
}
