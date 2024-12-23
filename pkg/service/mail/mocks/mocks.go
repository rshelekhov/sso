package mock

import (
	"context"
	"fmt"
	"time"
)

type Message struct {
	Subject   string
	Body      string
	Recipient string
	Timestamp time.Time
}

type Client struct {
	messages []Message
}

func NewClient() *Client {
	return &Client{
		messages: []Message{},
	}
}

func (c *Client) SendPlainText(_ context.Context, subject, body, recipient string) error {
	return c.send("Sending plain text", subject, body, recipient)
}

func (c *Client) SendHTML(_ context.Context, subject, body, recipient string) error {
	return c.send("Sending HTML", subject, body, recipient)
}

func (c *Client) Messages() []Message {
	return c.messages
}

func (c *Client) send(messageType, subject, body, recipient string) error {
	msg := Message{
		Subject:   subject,
		Body:      body,
		Recipient: recipient,
		Timestamp: time.Now(),
	}

	c.messages = append(c.messages, msg)
	c.printMessage(messageType, msg)

	return nil
}

func (c *Client) printMessage(action string, msg Message) {
	fmt.Printf("✉️: MOCK EMAIL SERVICE: %s\nsubject: %s\nbody: %s\nrecipient: %s\ntimestamp: %s\n\n",
		action, msg.Subject, msg.Body, msg.Recipient, msg.Timestamp)
}
