package config

import (
	"testing"
	"time"
)

func TestLoadRequiresEverySecuritySetting(t *testing.T) {
	for _, name := range []string{
		"DATABASE_URL",
		"LICENSE_HMAC_KEY",
		"HARDWARE_HMAC_KEY",
		"ED25519_PRIVATE_KEY",
		"LICENSE_ISSUER",
		"LICENSE_AUDIENCE",
		"PRODUCT",
		"ADMIN_SESSION_SECRET",
	} {
		t.Run(name, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(name, "")
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted missing %s", name)
			}
		})
	}
}

func TestLoadReturnsConfiguredValues(t *testing.T) {
	setRequiredEnvironment(t)
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.DatabaseURL != "postgres://user:pass@localhost:5432/starloader" || config.Product != "StarLoader" {
		t.Fatalf("Load() = %#v", config)
	}
}

func TestLoadRejectsReusedHMACKey(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("HARDWARE_HMAC_KEY", "license-hmac-key")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted identical license and hardware HMAC keys")
	}
}

func TestLoadDefaultsLoginTimeoutToTenSeconds(t *testing.T) {
	setRequiredEnvironment(t)

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.LoginTimeout != 10*time.Second {
		t.Fatalf("LoginTimeout = %s, want 10s", configuration.LoginTimeout)
	}
}

func TestLoadParsesConfiguredLoginTimeout(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("LOGIN_TIMEOUT", " 750ms ")

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.LoginTimeout != 750*time.Millisecond {
		t.Fatalf("LoginTimeout = %s, want 750ms", configuration.LoginTimeout)
	}
}

func TestLoadRejectsNonPositiveOrInvalidLoginTimeout(t *testing.T) {
	for _, value := range []string{"0", "0s", "-1s", "ten seconds"} {
		t.Run(value, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv("LOGIN_TIMEOUT", value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted LOGIN_TIMEOUT=%q", value)
			}
		})
	}
}

func TestLoadDefaultsAdminConsoleSettings(t *testing.T) {
	setRequiredEnvironment(t)

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.AdminAllowedOrigins) != 2 || configuration.AdminAllowedOrigins[0] != "http://localhost:3000" || configuration.AdminAllowedOrigins[1] != "http://127.0.0.1:3000" {
		t.Fatalf("AdminAllowedOrigins = %q, want localhost defaults", configuration.AdminAllowedOrigins)
	}
	if configuration.AdminSessionTTL != 12*time.Hour {
		t.Fatalf("AdminSessionTTL = %s, want 12h", configuration.AdminSessionTTL)
	}
	if configuration.AdminCookieSecure {
		t.Fatal("AdminCookieSecure should default to false")
	}
}

func TestLoadParsesAdminConsoleSettings(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ADMIN_ALLOWED_ORIGIN", "https://admin.example.com/")
	t.Setenv("ADMIN_SESSION_TTL", "2h")
	t.Setenv("ADMIN_COOKIE_SECURE", "true")

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.AdminAllowedOrigins) != 1 || configuration.AdminAllowedOrigins[0] != "https://admin.example.com" || configuration.AdminSessionTTL != 2*time.Hour || !configuration.AdminCookieSecure {
		t.Fatalf("Load() = %#v", configuration)
	}
}

func TestLoadRejectsInvalidAdminConsoleSettings(t *testing.T) {
	for _, setting := range []struct{ name, value string }{
		{"ADMIN_SESSION_TTL", "0s"},
		{"ADMIN_SESSION_TTL", "weekly"},
		{"ADMIN_COOKIE_SECURE", "maybe"},
	} {
		t.Run(setting.name+"="+setting.value, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(setting.name, setting.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%q", setting.name, setting.value)
			}
		})
	}
}

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("LOGIN_TIMEOUT", "")
	t.Setenv("ADMIN_ALLOWED_ORIGIN", "")
	t.Setenv("ADMIN_SESSION_TTL", "")
	t.Setenv("ADMIN_COOKIE_SECURE", "")
	for _, setting := range []struct{ name, value string }{
		{"DATABASE_URL", "postgres://user:pass@localhost:5432/starloader"},
		{"LICENSE_HMAC_KEY", "license-hmac-key"},
		{"HARDWARE_HMAC_KEY", "hardware-hmac-key"},
		{"ED25519_PRIVATE_KEY", "ed25519-private-key"},
		{"LICENSE_ISSUER", "starloader"},
		{"LICENSE_AUDIENCE", "starloader-client"},
		{"PRODUCT", "StarLoader"},
		{"ADMIN_SESSION_SECRET", "admin-session-secret"},
	} {
		t.Setenv(setting.name, setting.value)
	}
}
