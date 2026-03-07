package service

import (
	"fmt"
	"log"
	"os"

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

func (s *EmailService) SendVerificationEmail(toEmail string, token string) error {
	// Link de ejemplo (esto debería apuntar a tu UI front de activación)
	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "9009"
	}

	link := fmt.Sprintf("http://%s:%s/api/v1/reset-password?token=%s", host, port, token)
	subject := "Verifica tu cuenta en Peak Auth"
	html := fmt.Sprintf(`
		<h1>¡Bienvenido!</h1>
		<p>Has sido invitado a una aplicación gestionada por Peak Auth.</p>
		<p>Para activar tu cuenta y establecer tu contraseña, haz clic en el siguiente enlace:</p>
		<a href="%s" style="background: #4f46e5; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Activar Cuenta</a>
		<p>Si el botón no funciona, copia y pega esto: %s</p>
	`, link, link)

	return s.Provider.Send(subject, toEmail, html)
}
