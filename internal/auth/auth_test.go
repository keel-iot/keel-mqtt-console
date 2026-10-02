package auth

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keel-iot/keel-mqtt-console/internal/config"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword("correct horse battery staple", hash) {
		t.Fatal("expected password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("wrong password verified")
	}
}

func TestValidateRole(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "acl_admin", "admin"} {
		if !ValidateRole(role) {
			t.Fatalf("role %q should be valid", role)
		}
	}
	if ValidateRole("root") {
		t.Fatal("unexpected role accepted")
	}
}

func TestHTTPClientRejectsInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPClient(path); err == nil {
		t.Fatal("expected invalid CA to fail")
	}
}

func TestStartOIDCRedirectsWithRequest(t *testing.T) {
	a := &Authenticator{
		cfg: config.Config{
			AuthMode:        "oidc",
			OIDCClientID:    "console",
			OIDCRedirectURL: "https://console.example.test/auth/callback",
			SessionSecret:   strings.Repeat("s", 32),
		},
		oidc: oidcMetadata{AuthorizationEndpoint: "https://id.example.test/authorize"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "https://console.example.test/auth/login", nil)

	if err := a.StartOIDC(recorder, request); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 302 {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if !strings.HasPrefix(recorder.Header().Get("Location"), "https://id.example.test/authorize?") {
		t.Fatalf("unexpected redirect location: %s", recorder.Header().Get("Location"))
	}
}

func TestOIDCStateRoundTrip(t *testing.T) {
	a := &Authenticator{cfg: config.Config{SessionSecret: strings.Repeat("s", 32)}}
	state, err := a.signState("nonce", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	nonce, verifier, err := a.verifyState(state)
	if err != nil {
		t.Fatal(err)
	}
	if nonce != "nonce" || verifier != "verifier" {
		t.Fatalf("unexpected state: nonce=%q verifier=%q", nonce, verifier)
	}
}
