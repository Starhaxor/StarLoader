package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultLoginTimeout = 10 * time.Second

var requiredEnvironmentVariables = [...]string{
	"DATABASE_URL",
	"LICENSE_HMAC_KEY",
	"HARDWARE_HMAC_KEY",
	"ED25519_PRIVATE_KEY",
	"LICENSE_ISSUER",
	"LICENSE_AUDIENCE",
	"PRODUCT",
}

// Config contains the values required to operate the license service. Secrets
// are read only from the environment and must never be logged.
type Config struct {
	DatabaseURL       string
	LicenseHMACKey    string
	HardwareHMACKey   string
	Ed25519PrivateKey string
	LicenseIssuer     string
	LicenseAudience   string
	Product           string
	LoginTimeout      time.Duration
}

// Load reads the complete configuration, refusing to start when any required
// setting is missing or blank.
func Load() (Config, error) {
	values := make(map[string]string, len(requiredEnvironmentVariables))
	for _, name := range requiredEnvironmentVariables {
		value, ok := os.LookupEnv(name)
		if !ok || strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("required environment variable %s is not set", name)
		}
		values[name] = value
	}
	if values["LICENSE_HMAC_KEY"] == values["HARDWARE_HMAC_KEY"] {
		return Config{}, fmt.Errorf("LICENSE_HMAC_KEY and HARDWARE_HMAC_KEY must differ")
	}
	loginTimeout := defaultLoginTimeout
	if configuredTimeout := strings.TrimSpace(os.Getenv("LOGIN_TIMEOUT")); configuredTimeout != "" {
		parsedTimeout, err := time.ParseDuration(configuredTimeout)
		if err != nil || parsedTimeout <= 0 {
			return Config{}, fmt.Errorf("LOGIN_TIMEOUT must be a positive duration")
		}
		loginTimeout = parsedTimeout
	}

	return Config{
		DatabaseURL:       values["DATABASE_URL"],
		LicenseHMACKey:    values["LICENSE_HMAC_KEY"],
		HardwareHMACKey:   values["HARDWARE_HMAC_KEY"],
		Ed25519PrivateKey: values["ED25519_PRIVATE_KEY"],
		LicenseIssuer:     values["LICENSE_ISSUER"],
		LicenseAudience:   values["LICENSE_AUDIENCE"],
		Product:           values["PRODUCT"],
		LoginTimeout:      loginTimeout,
	}, nil
}
