package settings

import (
	"fmt"

	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
)

// MailServiceType - how to send email to clients
type MailServiceType string

const (
	MailServiceMailgun MailServiceType = "mailgun"
	MailServiceMock    MailServiceType = "mock"
)

type MailService struct {
	Type          MailServiceType `mapstructure:"EMAIL_SERVICE_TYPE" envDefault:"mock"`
	TemplatesPath string          `mapstructure:"EMAIL_TEMPLATES_PATH" envDefault:"./static/email_templates"`
	Mailgun       *MailgunParams
}

type MailgunParams struct {
	Domain        string `mapstructure:"EMAIL_MAILGUN_DOMAIN"`
	PrivateAPIKey string `mapstructure:"EMAIL_MAILGUN_PRIVATE_API_KEY"`
	Sender        string `mapstructure:"EMAIL_SENDER"`
}

func ToMailConfig(cfg MailService) (mail.Config, error) {
	const op = "settings.MailService.ToMailConfig"

	serviceType, err := validateAndConvertMailServiceType(cfg.Type)
	if err != nil {
		return mail.Config{}, fmt.Errorf("%s: %w", op, err)
	}

	mailConfig := mail.Config{
		Type:          serviceType,
		TemplatesPath: cfg.TemplatesPath,
	}

	if serviceType == mail.EmailServiceMailgun {
		// We checked that config fields are not empty when parsed env file
		mailConfig.Mailgun = &mail.MailgunParams{
			Domain: cfg.Mailgun.Domain,
			APIKey: cfg.Mailgun.PrivateAPIKey,
			Sender: cfg.Mailgun.Sender,
		}
	}

	return mailConfig, nil
}

func validateAndConvertMailServiceType(serviceType MailServiceType) (mail.EmailServiceType, error) {
	switch serviceType {
	case MailServiceMailgun:
		return mail.EmailServiceMailgun, nil
	case MailServiceMock:
		return mail.EmailServiceMock, nil
	case "":
		return "", fmt.Errorf("mail session type is empty")
	default:
		return "", fmt.Errorf("unknown mail session type: %s", serviceType)
	}
}
