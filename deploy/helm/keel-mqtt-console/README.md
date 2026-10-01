# keel-mqtt-console Helm chart

The chart deliberately refuses to render without:

- `auth.mode=local` or `auth.mode=oidc`;
- a broker management URL;
- a PostgreSQL URL Secret or value;
- a session secret;
- local bootstrap credentials, or complete OIDC settings.

For production, use existing Secrets rather than inline values. Example OIDC
deployment:

```sh
kubectl create secret generic keel-console-db \
  --from-literal=database-url='postgres://console:...@postgres/keel_console?sslmode=verify-full'
kubectl create secret generic keel-console-session \
  --from-literal=session-secret="$(openssl rand -base64 48)"
kubectl create secret generic keel-console-oidc \
  --from-literal=client-secret='...'

helm upgrade --install keel-mqtt-console . \
  --set auth.mode=oidc \
  --set broker.managementURL=http://keel-core:8090 \
  --set database.existingSecret=keel-console-db \
  --set session.existingSecret=keel-console-session \
  --set oidc.existingSecret=keel-console-oidc \
  --set oidc.issuerURL=https://id.example.com/realms/keel \
  --set oidc.clientID=keel-console \
  --set oidc.redirectURL=https://console.example.com/auth/callback \
  --set oidc.roleMapping='keel-console-viewer=viewer,keel-console-operator=operator,keel-console-admin=admin'
```
