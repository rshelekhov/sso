package mail

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail/mailgun"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail/mocks"
)

type EmailClient interface {
	SendPlainText(ctx context.Context, subject, body, recipient string) error
	SendHTML(ctx context.Context, subject, html, recipient string) error
}

type Service struct {
	client        EmailClient
	templatesPath string
}

const DefaultTemplatesPath = "./static/email_templates"

func NewService(cfg Config) *Service {
	var client EmailClient

	switch cfg.Type {
	case EmailServiceMailgun:
		client = mailgun.NewClient(cfg.Mailgun.Domain, cfg.Mailgun.APIKey, cfg.Mailgun.Sender)
	case EmailServiceMock:
		client = mocks.NewClient()
	}

	templatesPath := cfg.TemplatesPath
	if templatesPath == "" {
		templatesPath = DefaultTemplatesPath
	}

	return &Service{
		client:        client,
		templatesPath: templatesPath,
	}
}

type Data struct {
	TemplateType entity.EmailTemplateType
	Subject      string
	Recipient    string
	Data         map[string]string
}

func (s *Service) SendEmail(ctx context.Context, data Data) error {
	const method = "service.mail.SendEmail"

	templatePath := filepath.Join(s.getTemplatesPath(), data.TemplateType.FileName())

	templatesBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("%s: failed to read template file: %w", method, err)
	}

	tmpl := template.New(data.TemplateType.String())
	tmpl, err = tmpl.Parse(string(templatesBytes))
	if err != nil {
		return fmt.Errorf("%s: failed to parse template: %w", method, err)
	}

	var body bytes.Buffer
	if err = tmpl.Execute(&body, data.Data); err != nil {
		return fmt.Errorf("%s: failed to execute template: %w", method, err)
	}

	return s.client.SendHTML(ctx, data.Subject, body.String(), data.Recipient)
}

func (s *Service) getTemplatesPath() string {
	return s.templatesPath
}
