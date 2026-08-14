package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultLoginTimeout       = 10 * time.Second
	defaultAdminSessionTTL    = 12 * time.Hour
	defaultAdminAllowedOrigin = "http://localhost:3000"
)

var requiredEnvironmentVariables = [...]string{
	"DATABASE_URL",
	"LICENSE_HMAC_KEY",
	"HARDWARE_HMAC_KEY",
	"ED25519_PRIVATE_KEY",
	"LICENSE_ISSUER",
	"LICENSE_AUDIENCE",
	"PRODUCT",
	"ADMIN_SESSION_SECRET",
}

// Config contains the values required to operate the license service. Secrets
// are read only from the environment and must never be logged.
type Config struct {
	DatabaseURL         string
	LicenseHMACKey      string
	HardwareHMACKey     string
	Ed25519PrivateKey   string
	LicenseIssuer       string
	LicenseAudience     string
	Product             string
	LoginTimeout        time.Duration
	AdminConsoleEnabled bool
	AdminSessionSecret  string
	AdminAllowedOrigin  string
	AdminSessionTTL     time.Duration
	AdminCookieSecure   bool
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

	adminAllowedOrigin := defaultAdminAllowedOrigin
	if configuredOrigin := strings.TrimSpace(os.Getenv("ADMIN_ALLOWED_ORIGIN")); configuredOrigin != "" {
		adminAllowedOrigin = strings.TrimRight(configuredOrigin, "/")
	}
	adminSessionTTL := defaultAdminSessionTTL
	if configuredTTL := strings.TrimSpace(os.Getenv("ADMIN_SESSION_TTL")); configuredTTL != "" {
		parsedTTL, err := time.ParseDuration(configuredTTL)
		if err != nil || parsedTTL <= 0 {
			return Config{}, fmt.Errorf("ADMIN_SESSION_TTL must be a positive duration")
		}
		adminSessionTTL = parsedTTL
	}
	adminCookieSecure := false
	switch configuredSecure := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_COOKIE_SECURE"))); configuredSecure {
	case "", "false", "0":
		adminCookieSecure = false
	case "true", "1":
		adminCookieSecure = true
	default:
		return Config{}, fmt.Errorf("ADMIN_COOKIE_SECURE must be true or false")
	}
	adminConsoleEnabled := true
	switch configuredConsole := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_CONSOLE_ENABLED"))); configuredConsole {
	case "", "true", "1":
		adminConsoleEnabled = true
	case "false", "0":
		adminConsoleEnabled = false
	default:
		return Config{}, fmt.Errorf("ADMIN_CONSOLE_ENABLED must be true or false")
	}

	return Config{
		DatabaseURL:         values["DATABASE_URL"],
		LicenseHMACKey:      values["LICENSE_HMAC_KEY"],
		HardwareHMACKey:     values["HARDWARE_HMAC_KEY"],
		Ed25519PrivateKey:   values["ED25519_PRIVATE_KEY"],
		LicenseIssuer:       values["LICENSE_ISSUER"],
		LicenseAudience:     values["LICENSE_AUDIENCE"],
		Product:             values["PRODUCT"],
		LoginTimeout:        loginTimeout,
		AdminConsoleEnabled: adminConsoleEnabled,
		AdminSessionSecret:  values["ADMIN_SESSION_SECRET"],
		AdminAllowedOrigin:  adminAllowedOrigin,
		AdminSessionTTL:     adminSessionTTL,
		AdminCookieSecure:   adminCookieSecure,
	}, nil
}
