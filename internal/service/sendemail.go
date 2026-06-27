package service

import (
	"fmt"
	"log"
	"net/url"
	"os"
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
}

func (p *ResendProvider) Send(subject, toEmail, html string) error {
	client := resend.NewClient(p.ApiKey)
	params := &resend.SendEmailRequest{
		From:    p.From,
		To:      []string{toEmail},
		Subject: subject,
		Html:    html,
	}
	_, err := client.Emails.Send(params)
	return err
}

// ConsoleProvider solo imprime en consola (Desarrollo local)
type ConsoleProvider struct{}

func (p *ConsoleProvider) Send(subject, toEmail, html string) error {
	divider := "================================================================"
	log.Printf("\n%s\n📧 MOCK EMAIL SENT (LOCAL DEV)\nTo: %s\nSubject: %s\n\n%s\n%s",
		divider, toEmail, subject, html, divider)
	return nil
}

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
		provider = &ResendProvider{ApiKey: apiKey, From: from}
		log.Println("📧 Email Service initialized with RESEND provider")
	} else {
		provider = &ConsoleProvider{}
		log.Println("📧 Email Service initialized with CONSOLE (Mock) provider")
	}

	return &EmailService{Provider: provider}
}

func (s *EmailService) SendVerificationEmail(toEmail string, token string, appName string) error {
	if appName == "" {
		appName = "Peak Auth"
	}

	baseURL := util.BaseURL()
	link := fmt.Sprintf("%s/verify?token=%s", baseURL, url.QueryEscape(token))
	subject := fmt.Sprintf("Activa tu cuenta en %s", appName)

	logoURL := fmt.Sprintf("%s/static/img/logo.png", baseURL)
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

	logoURL := fmt.Sprintf("%s/static/img/logo.png", baseURL)
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

	logoURL := fmt.Sprintf("%s/static/img/logo.png", baseURL)
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
