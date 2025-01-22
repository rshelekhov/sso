package mailgun

import (
	"context"

	"github.com/mailgun/mailgun-go/v4"
)

type Client struct {
	mg     mailgun.Mailgun
	sender string
}

func NewClient(domain, apiKey, sender string) *Client {
	mg := mailgun.NewMailgun(domain, apiKey)
	return &Client{
		mg:     mg,
		sender: sender,
	}
}

func (c *Client) SendPlainText(ctx context.Context, subject, body, recipient string) error {
	message := c.mg.NewMessage(c.sender, subject, body, recipient)

	_, _, err := c.mg.Send(ctx, message)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) SendHTML(ctx context.Context, subject, html, recipient string) error {
	message := c.mg.NewMessage(c.sender, subject, "", recipient)
	message.SetHtml(html)
	_, _, err := c.mg.Send(ctx, message)
	if err != nil {
		return err
	}
	return nil
}
