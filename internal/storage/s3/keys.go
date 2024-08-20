package s3

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/rshelekhov/sso/internal/config/settings"
	"io"
)

type KeyStorage struct {
	Client         *s3.S3
	Bucket         string
	PrivateKeyPath string
}

func NewKeyStorage(settings settings.KeyStorageS3Params) (*KeyStorage, error) {
	s3Client, err := NewS3Client(
		settings.Region,
		settings.Endpoint,
		settings.AccessKey,
		settings.SecretKey)
	if err != nil {
		return nil, err
	}

	return &KeyStorage{
		Client:         s3Client,
		Bucket:         settings.Bucket,
		PrivateKeyPath: settings.PrivateKeyPath,
	}, nil
}

const privateKeyFilePathFormat = "%s/app_%s_private.pem"

func (s *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

	_, err := s.Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(privateKeyFilePath),
		Body:   bytes.NewReader(privateKeyPEM),
		ACL:    aws.String("private"),
	})
	if err != nil {
		return fmt.Errorf("failed to save private key to S3: %w", err)
	}

	return nil
}

func (s *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

	result, err := s.Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(privateKeyFilePath),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get private key from S3: %w", err)
	}
	defer result.Body.Close()

	privateKeyBytes, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key data: %w", err)
	}

	return privateKeyBytes, nil
}
