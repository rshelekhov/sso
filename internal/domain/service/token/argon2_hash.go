package token

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"golang.org/x/crypto/argon2"
	"strings"
)

func passwordHashArgon2(password string, p PasswordHashArgon2Params, salt, pepper []byte) string {
	saltAndPepper := combineSaltAndPepper(salt, pepper)

	hash := argon2.IDKey(
		[]byte(password),
		saltAndPepper,
		p.Time,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	// More details about this formatting can be found here:
	// https://github.com/P-H-C/phc-winner-argon2#command-line-utility
	hashStr := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		string(PasswordHashArgon2),
		argon2.Version,
		p.Memory,
		p.Time,
		p.Parallelism,
		saltBase64,
		hashBase64,
	)

	return hashStr
}

func passwordMatchArgon2(hashStr, password string, pepper []byte) (bool, error) {
	const method = "Service.token.PasswordMatchArgon2"

	p := PasswordHashArgon2Params{}
	parts := strings.Split(hashStr, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("%s: %w: %s", method, domain.ErrInvalidArgonHashString, hashStr)
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, fmt.Errorf("%s: %w: %d", method, domain.ErrUnSupportedArgon2Version, version)
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism)
	if err != nil {
		return false, fmt.Errorf("%s: %w", method, err)
	}

	saltBase64 := parts[4]
	hashBase64 := parts[5]

	salt, err := base64.RawStdEncoding.Strict().DecodeString(saltBase64)
	if err != nil {
		return false, fmt.Errorf("%s: %w", method, err)
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(hashBase64)
	if err != nil {
		return false, fmt.Errorf("%s: %w", method, err)
	}

	p.KeyLength = uint32(len(hash))

	saltAndPepper := combineSaltAndPepper(salt, pepper)

	computedHash := argon2.IDKey(
		[]byte(password),
		saltAndPepper,
		p.Time,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	// Compare the stored hash with the computed hash using ConstantTimeCompare.
	// This function performs the comparison in constant time, which is critical
	// to prevent timing attacks. Timing attacks exploit the time differences in
	// string comparisons to infer the correct password. By using a constant time
	// comparison, we ensure that the time taken to compare the hashes is the same
	// regardless of how much of the input matches, making it more secure.
	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return true, nil
	}

	return false, nil
}

// combineSaltAndPepper merges two byte slices, salt and pepper, into a single byte slice.
// It first pre-allocates a new slice with an exact combined capacity of both pepper and pepper.
// This is done using the length of pepper and pepper, which improves performance by avoiding
// multiple allocations as the slice grows dynamically during the append operations.
// By pre-allocating the necessary capacity, we minimize memory fragmentation and ensure
// that the final slice contains pepper followed by pepper in a single continuous block.
func combineSaltAndPepper(salt, pepper []byte) []byte {
	combined := make([]byte, 0, len(salt)+len(pepper))
	combined = append(combined, salt...)
	combined = append(combined, pepper...)
	return combined
}
