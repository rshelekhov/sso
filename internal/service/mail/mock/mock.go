package mock

import (
	"context"
	"fmt"
	"github.com/rshelekhov/sso/internal/port"
	"time"
)

// NewMailTransport creates new mail mock transport, all it does just print everything to console.
func NewMailTransport() port.MailTransport {
	return &EmailService{}
}

type EmailService struct {
	SendMessages []EmailMessage
}

type EmailMessage struct {
	Subject   string
	Body      string
	Recipient string
	Timestamp time.Time
}

// SendMessage simulates sending a plain text email
func (s *EmailService) SendMessage(ctx context.Context, subject, body, recipient string) error {
	msg := EmailMessage{
		Subject:   subject,
		Body:      body,
		Recipient: recipient,
		Timestamp: time.Now(),
	}

	s.printMessage("Sending message", msg)
	s.SendMessages = append(s.SendMessages, msg)
	return nil
}

// SendHTML simulates sending an HTML email
func (s *EmailService) SendHTML(ctx context.Context, subject, html, recipient string) error {
	msg := EmailMessage{
		Subject:   subject,
		Body:      html,
		Recipient: recipient,
		Timestamp: time.Now(),
	}

	s.printMessage("Sending HTML", msg)
	s.SendMessages = append(s.SendMessages, msg)
	return nil
}

func (s *EmailService) printMessage(action string, msg EmailMessage) {
	fmt.Printf("✉️: MOCK EMAIL SERVICE: %s\nsubject: %s\nbody: %s\nrecipient: %s\ntimestamp: %s\n\n",
		action, msg.Subject, msg.Body, msg.Recipient, msg.Timestamp)
}

// Messages returns all sent messages.
func (s *EmailService) Messages() []EmailMessage {
	return s.SendMessages
}
