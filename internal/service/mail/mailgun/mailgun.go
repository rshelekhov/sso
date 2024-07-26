package mailgun

import (
	"context"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/port"
)

const defaultTemplatesPath = "./static/email_templates"

func NewMailTransport(cfg *config.MailgunEmailServiceSettings) port.MailTransport {
	mg := mailgun.NewMailgun(cfg.Domain, cfg.PrivateAPIKey)
	return &mailService{
		mailgun:       mg,
		sender:        cfg.Sender,
		TemplatesPath: defaultTemplatesPath,
	}
}

type mailService struct {
	mailgun       mailgun.Mailgun
	sender        string
	TemplatesPath string
}

// SendMessage sends email with plain text.
func (s *mailService) SendMessage(ctx context.Context, subject, body, recipient string) error {
	message := s.mailgun.NewMessage(s.sender, subject, body, recipient)
	_, _, err := s.mailgun.Send(ctx, message)
	return err
}

// SendHTML sends email with html.
func (s *mailService) SendHTML(ctx context.Context, subject, html, recipient string) error {
	message := s.mailgun.NewMessage(s.sender, subject, "", recipient)
	message.SetHtml(html)
	_, _, err := s.mailgun.Send(ctx, message)
	return err
}
