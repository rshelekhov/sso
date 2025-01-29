package settings

import (
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/token"
)

// PasswordHashType - how to hash password
type PasswordHashType string

const (
	PasswordHashDefault PasswordHashType = "default"
	PasswordHashArgon2  PasswordHashType = "argon2"
	PasswordHashBcrypt  PasswordHashType = "bcrypt"
)

type PasswordHashParams struct {
	Type       PasswordHashType `mapstructure:"PASSWORD_HASH_TYPE" envDefault:"default"`
	SaltLength uint32           `mapstructure:"PASSWORD_HASH_SALT_LENGTH" envDefault:"24"`
	Pepper     string           `mapstructure:"PASSWORD_HASH_PEPPER" envDefault:"red-hot-chili-peppers"`
	Argon      *PasswordHashArgon2Params
	Bcrypt     *PasswordHashBcryptParams
}

type PasswordHashArgon2Params struct {
	Time        uint32 `mapstructure:"PASSWORD_HASH_ARGON2_TIME" envDefault:"2"`
	Memory      uint32 `mapstructure:"PASSWORD_HASH_ARGON2_MEMORY" envDefault:"24576"` // 24 * 1024
	Parallelism uint8  `mapstructure:"PASSWORD_HASH_ARGON2_PARALLELISM" envDefault:"2"`
	KeyLength   uint32 `mapstructure:"PASSWORD_HASH_ARGON2_KEY_LENGTH" envDefault:"24"`
}

type PasswordHashBcryptParams struct {
	Cost int `mapstructure:"PASSWORD_HASH_BCRYPT_COST" envDefault:"10"`
}

func ToPasswordHashConfig(params PasswordHashParams) (token.PasswordHashParams, error) {
	const op = "settings.PasswordHashParams.ToPasswordHashConfig"

	hashType, err := validateAndConvertPasswordHashType(params.Type)
	if err != nil {
		return token.PasswordHashParams{}, fmt.Errorf("%s: %w", op, err)
	}

	return token.PasswordHashParams{
		Type:       hashType,
		SaltLength: params.SaltLength,
		Pepper:     params.Pepper,
		Argon:      convertArgon2Params(params.Argon),
		Bcrypt:     convertBcryptParams(params.Bcrypt),
	}, nil
}

func validateAndConvertPasswordHashType(hashType PasswordHashType) (token.PasswordHashType, error) {
	switch hashType {
	case PasswordHashDefault:
		return token.PasswordHashDefault, nil
	case PasswordHashArgon2:
		return token.PasswordHashArgon2, nil
	case PasswordHashBcrypt:
		return token.PasswordHashBcrypt, nil
	case "":
		return "", fmt.Errorf("password hash type is empty")
	default:
		return "", fmt.Errorf("unknown password hash type: %s", hashType)
	}
}

func convertArgon2Params(params *PasswordHashArgon2Params) *token.PasswordHashArgon2Params {
	if params == nil {
		return nil
	}

	return &token.PasswordHashArgon2Params{
		Time:        params.Time,
		Memory:      params.Memory,
		Parallelism: params.Parallelism,
		KeyLength:   params.KeyLength,
	}
}

func convertBcryptParams(params *PasswordHashBcryptParams) *token.PasswordHashBcryptParams {
	if params == nil {
		return nil
	}

	return &token.PasswordHashBcryptParams{
		Cost: params.Cost,
	}
}
