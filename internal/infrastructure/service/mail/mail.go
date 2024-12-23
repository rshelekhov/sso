package mail

import (
	"context"
	"github.com/rshelekhov/sso/pkg/service/mail/mailgun"
	"github.com/rshelekhov/sso/pkg/service/mail/mocks"
)

type EmailClient interface {
	SendPlainText(ctx context.Context, subject, body, recipient string) error
	SendHTML(ctx context.Context, subject, html, recipient string) error
}

type Service struct {
	client        EmailClient
	templatesPath string
}

const defaultTemplatesPath = "./static/email_templates"

func NewService(cfg Config) *Service {
	var client EmailClient

	switch cfg.Type {
	case EmailServiceMailgun:
		client = mailgun.NewClient(cfg.Mailgun.Domain, cfg.Mailgun.APIKey, cfg.Mailgun.Sender)
	case EmailServiceMock:
		client = mocks.NewClient()
	}

	return &Service{
		client:        client,
		templatesPath: defaultTemplatesPath,
	}
}

func (s *Service) SendPlainText(ctx context.Context, subject, body, recipient string) error {
	return s.client.SendPlainText(ctx, subject, body, recipient)
}

func (s *Service) SendHTML(ctx context.Context, subject, html, recipient string) error {
	return s.client.SendHTML(ctx, subject, html, recipient)
}

func (s *Service) GetTemplatesPath() string {
	return s.templatesPath
}
