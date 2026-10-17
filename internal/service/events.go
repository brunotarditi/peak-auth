package service

import (
	"context"
	"fmt"
)

type Event struct {
	Name    string
	UserID  uint
	AppID   uint
	Email   string
	AppName string
	Token   string
}

type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

type noopEventPublisher struct{}

func (noopEventPublisher) Publish(context.Context, Event) error {
	return nil
}

func NewNoopEventPublisher() EventPublisher {
	return noopEventPublisher{}
}

type emailEventPublisher struct {
	emailService *EmailService
}

func NewEmailEventPublisher(emailService *EmailService) EventPublisher {
	if emailService == nil {
		return NewNoopEventPublisher()
	}
	return &emailEventPublisher{emailService: emailService}
}

func (p *emailEventPublisher) Publish(_ context.Context, event Event) error {
	switch event.Name {
	case "user.verification.requested":
		return p.emailService.SendVerificationEmail(event.Email, event.Token, event.AppName)
	default:
		return fmt.Errorf("evento no soportado: %s", event.Name)
	}
}
