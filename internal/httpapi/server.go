package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keel-iot/keel-mqtt-console/internal/auth"
	"github.com/keel-iot/keel-mqtt-console/internal/broker"
	"github.com/keel-iot/keel-mqtt-console/internal/config"
	"github.com/keel-iot/keel-mqtt-console/internal/store"
	"github.com/keel-iot/keel-mqtt-console/internal/web"
)

type Server struct {
	cfg    config.Config
	auth   *auth.Authenticator
	broker *broker.Client
	store  *store.Store
}

func New(cfg config.Config, a *auth.Authenticator, b *broker.Client, s *store.Store) *Server {
	return &Server{cfg: cfg, auth: a, broker: b, store: s}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	// Use an exact root pattern. With Go's method-aware ServeMux patterns,
	// "GET /" conflicts with the method-agnostic /api/broker/ subtree.
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/config", s.authConfig)
	mux.HandleFunc("POST /auth/login", s.loginLocal)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("/api/broker/", s.proxy)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && r.URL.Path != "/auth/login" && r.URL.Path != "/auth/config" && r.URL.Path != "/auth/callback" && r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") {
			if _, ok := s.currentUser(r); !ok && strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(web.Index)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthMode == "oidc" {
		if err := s.auth.StartOIDC(w, r); err != nil {
			writeError(w, 500, err.Error())
		}
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": "local"})
}

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"mode": s.cfg.AuthMode})
}

func (s *Server) loginLocal(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthMode != "local" {
		writeError(w, http.StatusNotFound, "local authentication is disabled")
		return
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&input) != nil {
		writeError(w, 400, "invalid request")
		return
	}
	token, user, err := s.auth.LoginLocal(r.Context(), input.Email, input.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	setSessionCookie(w, token, s.cfg.CookieSecure, s.cfg.SessionTTL)
	s.audit(user.Email, "login", "local")
	writeJSON(w, 200, map[string]any{"user": user})
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthMode != "oidc" {
		writeError(w, 404, "oidc authentication is disabled")
		return
	}
	token, user, err := s.auth.FinishOIDC(r.Context(), w, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	setSessionCookie(w, token, s.cfg.CookieSecure, s.cfg.SessionTTL)
	s.audit(user.Email, "login", "oidc")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if token := sessionToken(r); token != "" {
		_ = s.auth.Logout(r.Context(), token)
	}
	setSessionCookie(w, "", s.cfg.CookieSecure, -time.Hour)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, 401, "authentication required")
		return
	}
	csrf := ensureCSRF(w, r, s.cfg.CookieSecure)
	writeJSON(w, 200, map[string]any{"user": user, "csrf": csrf, "auth_mode": s.cfg.AuthMode})
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, 401, "authentication required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/broker")
	if r.Method != http.MethodGet {
		if !csrfOK(r) {
			writeError(w, http.StatusForbidden, "csrf validation failed")
			return
		}
		if strings.HasPrefix(path, "/api/acl/") && user.Role != "admin" && user.Role != "acl_admin" {
			writeError(w, 403, "acl_admin role required")
			return
		}
		if user.Role == "viewer" {
			writeError(w, 403, "operator role required")
			return
		}
	}
	resp, err := s.broker.Do(r.Context(), r.Method, path, r.Body)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	if r.Method != http.MethodGet {
		s.audit(user.Email, r.Method, path)
	}
}

func (s *Server) currentUser(r *http.Request) (auth.User, bool) {
	user, ok, _ := s.auth.Session(r.Context(), sessionToken(r))
	return user, ok
}
func (s *Server) audit(actor, action, target string) {
	go s.store.Audit(context.Background(), actor, action, target)
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie("console_session")
	if err != nil {
		return ""
	}
	return c.Value
}
func setSessionCookie(w http.ResponseWriter, value string, secure bool, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: "console_session", Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}
func ensureCSRF(w http.ResponseWriter, r *http.Request, secure bool) string {
	if c, err := r.Cookie("console_csrf"); err == nil && c.Value != "" {
		return c.Value
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: "console_csrf", Value: v, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
	return v
}
func csrfOK(r *http.Request) bool {
	c, err := r.Cookie("console_csrf")
	return err == nil && c.Value != "" && c.Value == r.Header.Get("X-CSRF-Token")
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

var _ = fmt.Sprintf
