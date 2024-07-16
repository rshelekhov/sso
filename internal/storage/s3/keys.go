package s3

import "github.com/aws/aws-sdk-go/service/s3"

type KeyStorage struct {
	Client   *s3.S3
	Bucket   string
	KeysPath string
}
