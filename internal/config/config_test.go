package config

import "testing"

func TestLoadRejectsMissingAuthMode(t *testing.T) {
	t.Setenv("CONSOLE_AUTH_MODE", "")
	t.Setenv("BROKER_MANAGEMENT_URL", "http://broker:8090")
	t.Setenv("CONSOLE_DATABASE_URL", "postgres://console@db/console")
	t.Setenv("CONSOLE_SESSION_SECRET", "12345678901234567890123456789012")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing auth mode to fail")
	}
}

func TestLoadLocalRequiresDatabase(t *testing.T) {
	t.Setenv("CONSOLE_AUTH_MODE", "local")
	t.Setenv("BROKER_MANAGEMENT_URL", "http://broker:8090")
	t.Setenv("CONSOLE_DATABASE_URL", "")
	t.Setenv("CONSOLE_SESSION_SECRET", "12345678901234567890123456789012")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing database to fail")
	}
}

func TestLoadOIDCRequiresRoleMapping(t *testing.T) {
	t.Setenv("CONSOLE_AUTH_MODE", "oidc")
	t.Setenv("BROKER_MANAGEMENT_URL", "http://broker:8090")
	t.Setenv("CONSOLE_DATABASE_URL", "postgres://console@db/console")
	t.Setenv("CONSOLE_SESSION_SECRET", "12345678901234567890123456789012")
	t.Setenv("OIDC_ISSUER_URL", "https://id.example.test")
	t.Setenv("OIDC_CLIENT_ID", "console")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("OIDC_REDIRECT_URL", "https://console.example.test/auth/callback")
	t.Setenv("OIDC_ROLE_MAPPING", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing oidc role mapping to fail")
	}
}
