package config

import "testing"

func TestLoadRequiresEverySecuritySetting(t *testing.T) {
	for _, name := range []string{
		"DATABASE_URL",
		"LICENSE_HMAC_KEY",
		"HARDWARE_HMAC_KEY",
		"ED25519_PRIVATE_KEY",
		"LICENSE_ISSUER",
		"LICENSE_AUDIENCE",
		"PRODUCT",
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

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	for _, setting := range []struct{ name, value string }{
		{"DATABASE_URL", "postgres://user:pass@localhost:5432/starloader"},
		{"LICENSE_HMAC_KEY", "license-hmac-key"},
		{"HARDWARE_HMAC_KEY", "hardware-hmac-key"},
		{"ED25519_PRIVATE_KEY", "ed25519-private-key"},
		{"LICENSE_ISSUER", "starloader"},
		{"LICENSE_AUDIENCE", "starloader-client"},
		{"PRODUCT", "StarLoader"},
	} {
		t.Setenv(setting.name, setting.value)
	}
}
