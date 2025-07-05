package config

import (
	"github.com/rshelekhov/sso/internal/config/settings"
)

type ServerSettings struct {
	App                 settings.App                 `yaml:"App"`
	GRPCServer          settings.GRPCServer          `yaml:"GRPCServer"`
	Storage             settings.Storage             `yaml:"Storage"`
	Cache               settings.Cache               `yaml:"Cache"`
	JWT                 settings.JWT                 `yaml:"JWT"`
	PasswordHash        settings.PasswordHashParams  `yaml:"PasswordHash"`
	KeyStorage          settings.KeyStorage          `yaml:"KeyStorage"`
	MailService         settings.MailService         `yaml:"MailService"`
	VerificationService settings.VerificationService `yaml:"VerificationService"`
}
