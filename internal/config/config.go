package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Addr                string
	AuthMode            string
	DatabaseURL         string
	BrokerManagementURL string
	SessionSecret       string
	BootstrapAdminEmail string
	BootstrapAdminPass  string
	OIDCIssuerURL       string
	OIDCClientID        string
	OIDCClientSecret    string
	OIDCRedirectURL     string
	OIDCGroupsClaim     string
	OIDCRoleMapping     map[string]string
	SessionTTL          time.Duration
	CookieSecure        bool
}

func Load() (Config, error) {
	c := Config{
		Addr:                env("CONSOLE_ADDR", ":8080"),
		AuthMode:            strings.ToLower(strings.TrimSpace(os.Getenv("CONSOLE_AUTH_MODE"))),
		DatabaseURL:         os.Getenv("CONSOLE_DATABASE_URL"),
		BrokerManagementURL: os.Getenv("BROKER_MANAGEMENT_URL"),
		SessionSecret:       os.Getenv("CONSOLE_SESSION_SECRET"),
		BootstrapAdminEmail: os.Getenv("CONSOLE_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPass:  os.Getenv("CONSOLE_BOOTSTRAP_ADMIN_PASSWORD"),
		OIDCIssuerURL:       strings.TrimRight(os.Getenv("OIDC_ISSUER_URL"), "/"),
		OIDCClientID:        os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:    os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:     os.Getenv("OIDC_REDIRECT_URL"),
		OIDCGroupsClaim:     env("OIDC_GROUPS_CLAIM", "groups"),
		OIDCRoleMapping:     parseMapping(os.Getenv("OIDC_ROLE_MAPPING")),
		SessionTTL:          8 * time.Hour,
		CookieSecure:        os.Getenv("CONSOLE_COOKIE_SECURE") == "true",
	}
	if v := os.Getenv("CONSOLE_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("invalid CONSOLE_SESSION_TTL: %q", v)
		}
		c.SessionTTL = d
	}
	if c.AuthMode != "local" && c.AuthMode != "oidc" {
		return Config{}, errors.New("CONSOLE_AUTH_MODE is required and must be local or oidc")
	}
	if c.BrokerManagementURL == "" {
		return Config{}, errors.New("BROKER_MANAGEMENT_URL is required")
	}
	if len(c.SessionSecret) < 32 {
		return Config{}, errors.New("CONSOLE_SESSION_SECRET must contain at least 32 bytes")
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("CONSOLE_DATABASE_URL is required for session storage")
	}
	if c.AuthMode == "oidc" {
		for name, value := range map[string]string{
			"OIDC_ISSUER_URL": c.OIDCIssuerURL, "OIDC_CLIENT_ID": c.OIDCClientID,
			"OIDC_CLIENT_SECRET": c.OIDCClientSecret, "OIDC_REDIRECT_URL": c.OIDCRedirectURL,
		} {
			if value == "" {
				return Config{}, fmt.Errorf("%s is required in oidc auth mode", name)
			}
		}
		if len(c.OIDCRoleMapping) == 0 {
			return Config{}, errors.New("OIDC_ROLE_MAPPING is required in oidc auth mode")
		}
	}
	return c, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func parseMapping(raw string) map[string]string {
	out := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		if ok && key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}
