package s3

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func NewS3Client(region, endpoint, accessKey, secretKey string) (*s3.S3, error) {
	cfg := getAWSConfig(region, endpoint, accessKey, secretKey)
	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create new s3 session: %v", err)
	}
	return s3.New(sess), nil
}

func getAWSConfig(region, endpoint, accessKey, secretKey string) *aws.Config {
	cfg := aws.NewConfig().
		WithHTTPClient(&http.Client{
			Timeout: 10 * time.Second,
		}).
		WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, "")).
		WithEndpoint(endpoint).
		WithRegion(region).
		WithCredentialsChainVerboseErrors(true)
	return cfg
}
