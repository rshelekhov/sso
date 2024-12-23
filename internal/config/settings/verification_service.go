package settings

import "time"

type VerificationService struct {
	TokenExpiryTime time.Duration `mapstructure:"VERIFICATION_TOKEN_EXPIRY_TIME" envDefault:"15m"`
}
