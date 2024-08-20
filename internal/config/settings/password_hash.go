package settings

import "golang.org/x/crypto/bcrypt"

// PasswordHashType - how to hash password
type PasswordHashType string

const (
	PasswordHashDefault PasswordHashType = "default"
	PasswordHashBcrypt  PasswordHashType = "bcrypt"
	PasswordHashArgon2  PasswordHashType = "argon2"
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

var (
	DefaultPasswordHashParams = PasswordHashParams{
		Type:       PasswordHashDefault,
		SaltLength: 32,
		Pepper:     "red-hot-chili-peppers",
		Argon:      &DefaultPasswordHashArgon2Params,
	}

	DefaultPasswordHashArgon2Params = PasswordHashArgon2Params{
		Time:        2,
		Memory:      32 * 1024,
		Parallelism: 2,
		KeyLength:   32,
	}

	DefaultPasswordHashBcryptParams = PasswordHashBcryptParams{
		Cost: bcrypt.DefaultCost,
	}
)
