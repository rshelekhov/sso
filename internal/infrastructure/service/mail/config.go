package mail

type EmailServiceType string

const (
	EmailServiceMailgun EmailServiceType = "mailgun"
	EmailServiceMock    EmailServiceType = "mock"
)

type Config struct {
	Type          EmailServiceType
	TemplatesPath string
	Mailgun       *MailgunParams
}

type MailgunParams struct {
	Domain string
	APIKey string
	Sender string
}
