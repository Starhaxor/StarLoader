package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16
	argonKeyLength   = 32
	argonParameters  = "m=65536,t=3,p=2"
)

// HashPassword derives an Argon2id password hash. The result includes every
// parameter needed by VerifyPassword to validate it in the future.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a password against an Argon2id hash without leaking
// the comparison result through an early exit.
func VerifyPassword(encoded, password string) (bool, error) {
	params, salt, expected, err := decodePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

type passwordParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func decodePasswordHash(encoded string) (passwordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return passwordParams{}, nil, nil, errors.New("invalid password hash format")
	}
	params := passwordParams{}
	if parts[3] != argonParameters {
		return passwordParams{}, nil, nil, errors.New("invalid password hash parameters")
	}
	params = passwordParams{memory: argonMemory, iterations: argonIterations, parallelism: argonParallelism}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return passwordParams{}, nil, nil, errors.New("invalid password hash salt")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) != argonKeyLength {
		return passwordParams{}, nil, nil, errors.New("invalid password hash value")
	}
	return params, salt, hash, nil
}
