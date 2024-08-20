package settings

// EmailServiceType - how to send email to clients
type EmailServiceType string

const (
	EmailServiceMailgun EmailServiceType = "mailgun"
	EmailServiceMock    EmailServiceType = "mock"
)

type EmailService struct {
	Type    EmailServiceType `mapstructure:"EMAIL_SERVICE_TYPE" envDefault:"mock"`
	Mailgun *MailgunParams
}

type MailgunParams struct {
	Domain        string `mapstructure:"EMAIL_MAILGUN_DOMAIN"`
	PrivateAPIKey string `mapstructure:"EMAIL_MAILGUN_PRIVATE_API_KEY"`
	Sender        string `mapstructure:"EMAIL_SENDER"`
}
