package mail

import (
	"context"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/service/mail/mailgun"
	"github.com/rshelekhov/sso/internal/service/mail/mock"
)

const defaultTemplatesPath = "./static/email_templates"

func NewMailService(ess settings.EmailService) port.MailService {
	var s port.MailTransport

	switch ess.Type {
	case settings.EmailServiceMailgun:
		s = mailgun.NewMailTransport(ess.Mailgun)
	case settings.EmailServiceMock:
		s = mock.NewMailTransport()
	}

	return &EmailService{
		service:       s,
		templatesPath: defaultTemplatesPath,
	}
}

type EmailService struct {
	service       port.MailTransport
	templatesPath string
}

func (s *EmailService) SendMessage(ctx context.Context, subject, body, recipient string) error {
	return s.service.SendMessage(ctx, subject, body, recipient)
}

func (s *EmailService) SendHTML(ctx context.Context, subject, html, recipient string) error {
	return s.service.SendHTML(ctx, subject, html, recipient)
}

func (s *EmailService) GetTemplatesPath() string {
	return s.templatesPath
}
