package service

import (
	"os"

	"github.com/resend/resend-go/v2"
)

func sendVerificationEmail(subject, toEmail, html string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    "Librería Mariela <no-reply@brunotarditi.com>",
		To:      []string{toEmail},
		Subject: subject,
		Html:    html,
	}
	_, err := client.Emails.Send(params)
	if err != nil {
		panic(err)
	}
	return err
}
