package s3

import (
	"bytes"
	"fmt"
	storage "github.com/rshelekhov/sso/pkg/storage/s3"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

type KeyStorage struct {
	Client         *s3.S3
	Bucket         string
	PrivateKeyPath string
}

func NewKeyStorage(cfg Config) (*KeyStorage, error) {
	s3Client, err := storage.NewS3Client(
		cfg.Region,
		cfg.Endpoint,
		cfg.AccessKey,
		cfg.SecretKey,
	)
	if err != nil {
		return nil, err
	}

	return &KeyStorage{
		Client:         s3Client,
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

func (s *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	const method = "service.token.SavePrivateKey"

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

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

func (s *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	const method = "service.token.GetPrivateKey"

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

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
