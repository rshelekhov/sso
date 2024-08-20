package jwtoken

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
)

// Parameters for Argon2
var (
	iterations  uint32 = 3
	memory      uint32 = 64 * 1024
	parallelism uint8  = 2
	keyLength   uint32 = 32
)

func PasswordHashArgon2(password string, salt []byte) (string, error) {
	const method = "jwt.PasswordHashArgon2"

	if password == "" {
		return "", fmt.Errorf("%s: password is empty", method)
	}
	if len(salt) == 0 {
		return "", fmt.Errorf("%s: salt is empty", method)
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	hashBase64 := base64.StdEncoding.EncodeToString(hash)
	return hashBase64, nil
}

func PasswordMatchArgon2(hash, password string, salt []byte) (bool, error) {
	const method = "jwt.PasswordMatchArgon2"

	if hash == "" {
		return false, fmt.Errorf("%s: hash is empty", method)
	} else if password == "" {
		return false, fmt.Errorf("%s: password is empty", method)
	} else if len(salt) == 0 {
		return false, fmt.Errorf("%s: salt is empty", method)
	}

}
