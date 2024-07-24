package port

import "context"

type MailService interface {
	SendMessage(ctx context.Context, subject, body, recipient string) error
	SendHTML(ctx context.Context, subject, html, recipient string) error
	GetTemplatesPath() string
}
