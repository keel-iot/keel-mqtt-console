package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keel-iot/keel-mqtt-console/internal/config"
	"github.com/keel-iot/keel-mqtt-console/internal/store"
	"golang.org/x/crypto/argon2"
)

type User struct{ Email, Role string }

type Authenticator struct {
	cfg    config.Config
	store  *store.Store
	http   *http.Client
	oidc   oidcMetadata
	keysMu sync.Mutex
	keys   oidcJWKS
}

type oidcMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}
type oidcJWKS struct {
	Keys    []jwk `json:"keys"`
	fetched time.Time
}
type jwk struct {
	KTY string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func New(ctx context.Context, cfg config.Config, db *store.Store) (*Authenticator, error) {
	_ = ctx
	httpClient, err := newHTTPClient(cfg.OIDCCAFile)
	if err != nil {
		return nil, fmt.Errorf("oidc tls: %w", err)
	}
	a := &Authenticator{cfg: cfg, store: db, http: httpClient}
	if cfg.AuthMode != "oidc" {
		return a, nil
	}
	resp, err := a.http.Get(cfg.OIDCIssuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery returned %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&a.oidc); err != nil {
		return nil, fmt.Errorf("oidc discovery decode: %w", err)
	}
	if a.oidc.AuthorizationEndpoint == "" || a.oidc.TokenEndpoint == "" || a.oidc.JWKSURI == "" || a.oidc.Issuer == "" {
		return nil, errors.New("oidc discovery is missing required endpoints")
	}
	if a.oidc.Issuer != cfg.OIDCIssuerURL {
		return nil, errors.New("oidc discovery issuer does not match OIDC_ISSUER_URL")
	}
	return a, nil
}

func newHTTPClient(caFile string) (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if caFile == "" {
		return client, nil
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", caFile, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q does not contain a valid PEM certificate", caFile)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not a *http.Transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	client.Transport = transport
	return client, nil
}

func (a *Authenticator) LoginLocal(ctx context.Context, email, password string) (string, User, error) {
	if a.cfg.AuthMode != "local" {
		return "", User{}, errors.New("local authentication is disabled")
	}
	u, err := a.store.FindUser(ctx, email)
	if err != nil || !u.Enabled || !verifyPassword(password, u.PasswordHash) {
		return "", User{}, errors.New("invalid credentials")
	}
	token, err := randomString(32)
	if err != nil {
		return "", User{}, err
	}
	if err := a.store.CreateSession(ctx, token, u.Email, u.Role, &u.ID, time.Now().Add(a.cfg.SessionTTL)); err != nil {
		return "", User{}, err
	}
	return token, User{Email: u.Email, Role: u.Role}, nil
}

func (a *Authenticator) NewSession(ctx context.Context, email, role string) (string, error) {
	token, err := randomString(32)
	if err != nil {
		return "", err
	}
	if err := a.store.CreateSession(ctx, token, email, role, nil, time.Now().Add(a.cfg.SessionTTL)); err != nil {
		return "", err
	}
	return token, nil
}

func (a *Authenticator) Session(ctx context.Context, token string) (User, bool, error) {
	if token == "" {
		return User{}, false, nil
	}
	email, role, ok, err := a.store.Session(ctx, token)
	return User{Email: email, Role: role}, ok, err
}

func (a *Authenticator) Logout(ctx context.Context, token string) error {
	return a.store.DeleteSession(ctx, token)
}

func (a *Authenticator) StartOIDC(w http.ResponseWriter, r *http.Request) error {
	if a.cfg.AuthMode != "oidc" {
		return errors.New("oidc authentication is disabled")
	}
	nonce, err := randomString(24)
	if err != nil {
		return err
	}
	verifier, err := randomString(32)
	if err != nil {
		return err
	}
	state, err := a.signState(nonce, verifier)
	if err != nil {
		return err
	}
	setCookie(w, "oidc_state", state, a.cfg.CookieSecure, 10*time.Minute)
	v := url.Values{}
	v.Set("client_id", a.cfg.OIDCClientID)
	v.Set("redirect_uri", a.cfg.OIDCRedirectURL)
	v.Set("response_type", "code")
	v.Set("scope", "openid profile email")
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("code_challenge", pkceChallenge(verifier))
	v.Set("code_challenge_method", "S256")
	http.Redirect(w, r, a.oidc.AuthorizationEndpoint+"?"+v.Encode(), http.StatusFound)
	return nil
}

func (a *Authenticator) FinishOIDC(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, User, error) {
	if r.URL.Query().Get("error") != "" {
		return "", User{}, fmt.Errorf("oidc login failed: %s", r.URL.Query().Get("error"))
	}
	cookie, err := r.Cookie("oidc_state")
	if err != nil {
		return "", User{}, errors.New("missing oidc state cookie")
	}
	state := r.URL.Query().Get("state")
	if state == "" || !secureCompare(state, cookie.Value) {
		return "", User{}, errors.New("invalid oidc state")
	}
	setCookie(w, "oidc_state", "", a.cfg.CookieSecure, -time.Hour)
	nonce, verifier, err := a.verifyState(state)
	if err != nil {
		return "", User{}, err
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return "", User{}, errors.New("oidc callback missing code")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {a.cfg.OIDCRedirectURL}, "client_id": {a.cfg.OIDCClientID}, "client_secret": {a.cfg.OIDCClientSecret}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.oidc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", User{}, fmt.Errorf("oidc token exchange returned %s", resp.Status)
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", User{}, err
	}
	claims, err := a.verifyIDToken(tokenResp.IDToken, nonce)
	if err != nil {
		return "", User{}, err
	}
	email := stringClaim(claims, "email")
	if email == "" {
		email = stringClaim(claims, "preferred_username")
	}
	if email == "" {
		return "", User{}, errors.New("oidc token has no email or preferred_username")
	}
	role := a.roleFromClaims(claims)
	if role == "" {
		return "", User{}, errors.New("oidc user has no mapped console role")
	}
	session, err := a.NewSession(ctx, email, role)
	return session, User{Email: email, Role: role}, err
}

func (a *Authenticator) BootstrapLocal(ctx context.Context) error {
	if a.cfg.AuthMode != "local" {
		return nil
	}
	n, err := a.store.UserCount(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if a.cfg.BootstrapAdminEmail == "" || a.cfg.BootstrapAdminPass == "" {
		return errors.New("local auth has no users; bootstrap admin credentials are required")
	}
	hash, err := hashPassword(a.cfg.BootstrapAdminPass)
	if err != nil {
		return err
	}
	return a.store.CreateUser(ctx, a.cfg.BootstrapAdminEmail, hash, "admin")
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return "argon2id$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func verifyPassword(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 3 || p[0] != "argon2id" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[1])
	expected, err2 := base64.RawStdEncoding.DecodeString(p[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, uint32(len(expected)))
	return hmac.Equal(got, expected)
}

func (a *Authenticator) signState(nonce, verifier string) (string, error) {
	payload, err := json.Marshal(struct {
		Nonce    string `json:"nonce"`
		Verifier string `json:"verifier"`
		Exp      int64  `json:"exp"`
	}{
		Nonce:    nonce,
		Verifier: verifier,
		Exp:      time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	data := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(data))
	return data + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (a *Authenticator) verifyState(value string) (string, string, error) {
	p := strings.Split(value, ".")
	if len(p) != 2 {
		return "", "", errors.New("invalid oidc state")
	}
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(p[0]))
	expected, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil || !hmac.Equal(mac.Sum(nil), expected) {
		return "", "", errors.New("invalid oidc state signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil {
		return "", "", err
	}
	var v struct {
		Nonce    string `json:"nonce"`
		Verifier string `json:"verifier"`
		Exp      int64  `json:"exp"`
	}
	if json.Unmarshal(data, &v) != nil || v.Exp < time.Now().Unix() {
		return "", "", errors.New("expired oidc state")
	}
	return v.Nonce, v.Verifier, nil
}

func (a *Authenticator) verifyIDToken(raw, nonce string) (jwt.MapClaims, error) {
	keys, err := a.jwks()
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		for _, key := range keys.Keys {
			if key.Kid == kid {
				return key.publicKey()
			}
		}
		return nil, errors.New("oidc signing key not found")
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid oidc id_token: %w", err)
	}
	if stringClaim(claims, "iss") != a.cfg.OIDCIssuerURL || !audienceContains(claims["aud"], a.cfg.OIDCClientID) || stringClaim(claims, "nonce") != nonce {
		return nil, errors.New("oidc id_token claims validation failed")
	}
	return claims, nil
}

func (a *Authenticator) jwks() (oidcJWKS, error) {
	a.keysMu.Lock()
	defer a.keysMu.Unlock()
	if time.Since(a.keys.fetched) < 5*time.Minute && len(a.keys.Keys) > 0 {
		return a.keys, nil
	}
	resp, err := a.http.Get(a.oidc.JWKSURI)
	if err != nil {
		return oidcJWKS{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcJWKS{}, fmt.Errorf("jwks returned %s", resp.Status)
	}
	var keys oidcJWKS
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return oidcJWKS{}, err
	}
	keys.fetched = time.Now()
	a.keys = keys
	return keys, nil
}

func (k jwk) publicKey() (any, error) {
	decode := func(v string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(v) }
	switch k.KTY {
	case "RSA":
		n, err := decode(k.N)
		if err != nil {
			return nil, err
		}
		e, err := decode(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		xb, err := decode(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := decode(k.Y)
		if err != nil {
			return nil, err
		}
		curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
		if curve == nil {
			return nil, errors.New("unsupported oidc EC curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	}
	return nil, errors.New("unsupported oidc key type")
}

func (a *Authenticator) roleFromClaims(c jwt.MapClaims) string {
	if len(a.cfg.OIDCRoleMapping) == 0 {
		return "viewer"
	}
	if raw, ok := c[a.cfg.OIDCGroupsClaim].([]any); ok {
		for _, item := range raw {
			if role := a.cfg.OIDCRoleMapping[fmt.Sprint(item)]; ValidateRole(role) {
				return role
			}
		}
	}
	if raw, ok := c[a.cfg.OIDCGroupsClaim].(string); ok {
		role := a.cfg.OIDCRoleMapping[raw]
		if ValidateRole(role) {
			return role
		}
	}
	return ""
}

func stringClaim(c jwt.MapClaims, name string) string { v, _ := c[name].(string); return v }
func audienceContains(value any, want string) bool {
	switch v := value.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if item == want {
				return true
			}
		}
	}
	return false
}
func randomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func secureCompare(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
func setCookie(w http.ResponseWriter, name, value string, secure bool, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds())})
}

func ValidateRole(role string) bool {
	return role == "viewer" || role == "operator" || role == "acl_admin" || role == "admin"
}
