package settings

import "time"

type VerificationService struct {
	TokenExpiryTime  time.Duration `yaml:"TokenExpiryTime" default:"15m"`
	VerificationURL  string        `yaml:"VerificationURL" default:"http://localhost:3000/verify-email?token="`
	ResetPasswordURL string        `yaml:"ResetPasswordURL" default:"http://localhost:3000/reset-password?token="`
}
