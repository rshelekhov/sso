package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"

	s3lib "github.com/rshelekhov/golib/db/s3"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

type KeyStorage struct {
	Client         *s3.S3
	Bucket         string
	PrivateKeyPath string
}

func NewKeyStorage(ctx context.Context, cfg Config) (*KeyStorage, error) {
	const op = "storage.key.s3.NewKeyStorage"

	conn, err := s3lib.NewConnection(ctx,
		s3lib.WithRegion(cfg.Region),
		s3lib.WithEndpoint(cfg.Endpoint),
		s3lib.WithCredentials(cfg.AccessKey, cfg.SecretKey),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create s3 connection: %w", op, err)
	}

	return &KeyStorage{
		Client:         conn.Client(),
		Bucket:         cfg.Bucket,
		PrivateKeyPath: cfg.PrivateKeyPath,
	}, nil
}

type Config struct {
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	PrivateKeyPath string
	Endpoint       string
}

const privateKeyFilePathFormat = "%s/app_%s_private.pem"

func (s *KeyStorage) SavePrivateKey(clientID string, privateKeyPEM []byte) error {
	const method = "storage.key.s3.SavePrivateKey"

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, clientID)

	_, err := s.Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(privateKeyFilePath),
		Body:   bytes.NewReader(privateKeyPEM),
		ACL:    aws.String("private"),
	})
	if err != nil {
		return fmt.Errorf("%s: failed to save private key to S3: %w", method, err)
	}

	return nil
}

func (s *KeyStorage) GetPrivateKey(clientID string) ([]byte, error) {
	const method = "storage.key.s3.GetPrivateKey"

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, clientID)

	result, err := s.Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(privateKeyFilePath),
	})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get private key from S3: %w", method, err)
	}
	defer result.Body.Close()

	privateKeyBytes, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("%s:failed to read private key data: %w", method, err)
	}

	return privateKeyBytes, nil
}
