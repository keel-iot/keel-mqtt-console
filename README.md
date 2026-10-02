# Keel MQTT Console

Standalone web console for Keel MQTT Gateway.

The console is a Go binary with an embedded UI and a small authenticated BFF
that proxies the broker management API. It supports exactly one authentication
mode per deployment:

- `local`: users/passwords stored in PostgreSQL, passwords hashed with Argon2id;
- `oidc`: generic OIDC Authorization Code flow with PKCE, suitable for Okta,
  Keycloak, Clavex and other conforming providers.

The process refuses to start when `CONSOLE_AUTH_MODE` is missing or when the
selected mode is incomplete.

## Run locally

```sh
export CONSOLE_AUTH_MODE=local
export CONSOLE_DATABASE_URL='postgres://console:console@localhost:5432/keel_console?sslmode=disable'
export CONSOLE_SESSION_SECRET='replace-with-at-least-32-random-bytes'
export BROKER_MANAGEMENT_URL='http://localhost:18090'
export CONSOLE_BOOTSTRAP_ADMIN_EMAIL='admin@example.com'
export CONSOLE_BOOTSTRAP_ADMIN_PASSWORD='change-me-now'
go run ./cmd/console
```

Open <http://localhost:8080>. The bootstrap credentials are used only when the
local user table is empty.

## OIDC configuration

```sh
export CONSOLE_AUTH_MODE=oidc
export CONSOLE_SESSION_SECRET='at-least-32-random-bytes'
export BROKER_MANAGEMENT_URL='http://keel-core:8090'
export OIDC_ISSUER_URL='https://id.example.com/realms/keel'
export OIDC_CLIENT_ID='keel-console'
export OIDC_CLIENT_SECRET='...'
export OIDC_REDIRECT_URL='https://console.example.com/auth/callback'
export OIDC_GROUPS_CLAIM=groups
export OIDC_ROLE_MAPPING='keel-console-viewer=viewer,keel-console-operator=operator,keel-console-admin=admin'
```

The OIDC client must allow the exact redirect URL. The console validates issuer,
audience, expiry and the signing key from the provider's JWKS endpoint.

For an OIDC provider using an internal or self-signed CA, set `OIDC_CA_FILE`
to a PEM bundle. The CA is added to the system trust store; certificate
verification is not disabled.

## Docker

```sh
docker build -t keel-mqtt-console:dev .
docker run --rm -p 8080:8080 --env-file .env keel-mqtt-console:dev
```

## Kubernetes

The Helm chart is under `deploy/helm/keel-mqtt-console`.

```sh
helm upgrade --install keel-mqtt-console deploy/helm/keel-mqtt-console \
  --set broker.managementURL=http://keel-core:8090 \
  --set auth.mode=oidc \
  --set oidc.issuerURL=https://id.example.com/realms/keel \
  --set oidc.clientID=keel-console \
  --set oidc.redirectURL=https://console.example.com/auth/callback \
  --set oidc.existingSecret=keel-console-oidc
```

For production, put the database URL, session secret and OIDC client secret in
Kubernetes Secrets. The chart intentionally has no insecure default auth mode.

## Dashboard behavior

The dashboard supports manual refresh and optional automatic refresh. The
selected interval (5 seconds to 5 minutes) is stored in the browser and
automatic refresh pauses while the tab is hidden. Client search and
pagination are delegated to the broker management API so the browser does
not need to load the whole connected-client fleet.

The paginated client API accepts:

```text
GET /api/live/clients?page=1&page_size=50&search=device-1&node_id=edge-1
```

The broker metrics view exposes the latest message rate plus rolling 1-minute
and 5-minute averages, persistent offline sessions, recent disconnects and
recent drops observed in the broker data path.
