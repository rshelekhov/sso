package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	s3lib "github.com/rshelekhov/golib/db/s3"
	"github.com/rshelekhov/sso/internal/observability/metrics"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

type KeyStorage struct {
	Client         *s3.S3
	Bucket         string
	PrivateKeyPath string
	recorder       metrics.MetricsRecorder
}

func NewKeyStorage(ctx context.Context, cfg Config, recorder metrics.MetricsRecorder) (*KeyStorage, error) {
	const op = "storage.key.s3.NewKeyStorage"

	var conn s3lib.ConnectionAPI
	var err error

	if cfg.ForcePathStyle {
		// For MinIO or S3-compatible services that require path-style URLs
		conn, err = s3lib.NewConnection(ctx,
			s3lib.WithRegion(cfg.Region),
			s3lib.WithEndpoint(cfg.Endpoint),
			s3lib.WithCredentials(cfg.AccessKey, cfg.SecretKey),
			s3lib.WithForcePathStyle(true),
			s3lib.WithDisableSSL(cfg.DisableSSL),
		)
	} else {
		// For AWS S3 (virtual-hosted-style URLs)
		if cfg.Endpoint != "" {
			conn, err = s3lib.NewConnection(ctx,
				s3lib.WithRegion(cfg.Region),
				s3lib.WithEndpoint(cfg.Endpoint),
				s3lib.WithCredentials(cfg.AccessKey, cfg.SecretKey),
				s3lib.WithDisableSSL(cfg.DisableSSL),
			)
		} else {
			// Default AWS S3 (no custom endpoint)
			conn, err = s3lib.NewConnection(ctx,
				s3lib.WithRegion(cfg.Region),
				s3lib.WithCredentials(cfg.AccessKey, cfg.SecretKey),
				s3lib.WithDisableSSL(cfg.DisableSSL),
			)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("%s: failed to create s3 connection: %w", op, err)
	}

	return &KeyStorage{
		Client:         conn.Client(),
		Bucket:         cfg.Bucket,
		PrivateKeyPath: cfg.PrivateKeyPath,
		recorder:       recorder,
	}, nil
}

type Config struct {
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	PrivateKeyPath string
	Endpoint       string
	ForcePathStyle bool
	DisableSSL     bool
}

const privateKeyFilePathFormat = "%s/app_%s_private.pem"

func (s *KeyStorage) SavePrivateKey(clientID string, privateKeyPEM []byte) error {
	const method = "storage.key.s3.SavePrivateKey"

	start := time.Now()

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

	s.recorder.RecordS3Operation(method, time.Since(start), err)

	return nil
}

func (s *KeyStorage) GetPrivateKey(clientID string) ([]byte, error) {
	const method = "storage.key.s3.GetPrivateKey"

	start := time.Now()

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

	s.recorder.RecordS3Operation(method, time.Since(start), err)

	return privateKeyBytes, nil
}
