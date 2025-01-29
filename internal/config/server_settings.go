package config

import (
	"github.com/rshelekhov/sso/internal/config/settings"
)

type ServerSettings struct {
	AppEnv              string                       `mapstructure:"APP_ENV"`
	GRPCServer          settings.GRPCServer          `mapstructure:",squash"`
	HTTPServer          settings.HTTPServer          `mapstructure:",squash"`
	Storage             settings.Storage             `mapstructure:",squash"`
	JWT                 settings.JWT                 `mapstructure:",squash"`
	PasswordHash        settings.PasswordHashParams  `mapstructure:",squash"`
	KeyStorage          settings.KeyStorage          `mapstructure:",squash"`
	MailService         settings.MailService         `mapstructure:",squash"`
	VerificationService settings.VerificationService `mapstructure:",squash"`
}
