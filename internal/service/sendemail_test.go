package service

import (
	"strings"
	"testing"
)

type mockEmailProviderCapture struct {
	lastSubject string
	lastToEmail string
	lastHTML    string
}

func (m *mockEmailProviderCapture) Send(subject, toEmail, html string) error {
	m.lastSubject = subject
	m.lastToEmail = toEmail
	m.lastHTML = html
	return nil
}

func TestConsoleProvider_Send(t *testing.T) {
	provider := &ConsoleProvider{}
	err := provider.Send("Test Subject", "user@test.local", "<p>Hello</p>")
	if err != nil {
		t.Fatalf("ConsoleProvider.Send no debió retornar error: %v", err)
	}
}

func TestEmailService_SendVerificationEmail(t *testing.T) {
	mockProv := &mockEmailProviderCapture{}
	svc := &EmailService{Provider: mockProv}

	err := svc.SendVerificationEmail("user@peak.local", "token12345", "Test App")
	if err != nil {
		t.Fatalf("SendVerificationEmail falló: %v", err)
	}

	if mockProv.lastToEmail != "user@peak.local" {
		t.Errorf("destinatario incorrecto: %s", mockProv.lastToEmail)
	}
	if !strings.Contains(mockProv.lastSubject, "Activa tu cuenta") {
		t.Errorf("asunto incorrecto: %s", mockProv.lastSubject)
	}
	if !strings.Contains(mockProv.lastHTML, "token12345") {
		t.Errorf("HTML no contiene el token de verificación")
	}
}

func TestEmailService_SendPasswordResetEmail(t *testing.T) {
	mockProv := &mockEmailProviderCapture{}
	svc := &EmailService{Provider: mockProv}

	err := svc.SendPasswordResetEmail("user@peak.local", "resettoken99")
	if err != nil {
		t.Fatalf("SendPasswordResetEmail falló: %v", err)
	}

	if mockProv.lastToEmail != "user@peak.local" {
		t.Errorf("destinatario incorrecto: %s", mockProv.lastToEmail)
	}
	if !strings.Contains(mockProv.lastSubject, "Restablece tu contraseña") {
		t.Errorf("asunto incorrecto: %s", mockProv.lastSubject)
	}
	if !strings.Contains(mockProv.lastHTML, "resettoken99") {
		t.Errorf("HTML no contiene el token de reseteo")
	}
}

func TestEmailService_SendActivationEmail(t *testing.T) {
	mockProv := &mockEmailProviderCapture{}
	svc := &EmailService{Provider: mockProv}

	err := svc.SendActivationEmail("user@peak.local", "activatetoken77", "Mi App")
	if err != nil {
		t.Fatalf("SendActivationEmail falló: %v", err)
	}

	if mockProv.lastToEmail != "user@peak.local" {
		t.Errorf("destinatario incorrecto: %s", mockProv.lastToEmail)
	}
	if !strings.Contains(mockProv.lastSubject, "Activa tu cuenta") {
		t.Errorf("asunto incorrecto: %s", mockProv.lastSubject)
	}
	if !strings.Contains(mockProv.lastHTML, "activatetoken77") {
		t.Errorf("HTML no contiene el token de activación")
	}
}
