# Google OAuth on Kubernetes

`scia` can store Google OAuth refresh tokens in per-user Kubernetes Secrets instead of
the local SQLite store. Use this when running separate OAuth and proxy deployments in
Kubernetes.

## Secret store mode

Set `server.secrets.mode` to `kubernetes` and define one Secret per user under
`server.users`:

```yaml
server:
  secrets:
    mode: kubernetes
    kubernetes:
      namespace: scia
  users:
    alice:
      secretName: scia-oauth-alice
    bob:
      secretName: scia-oauth-bob
```

In-cluster, `scia` uses the pod service account. Outside the cluster, it falls back to
`KUBECONFIG` or the default kubeconfig.

## OAuth server

Example config: [configs/oauth-kubernetes.yaml](../configs/oauth-kubernetes.yaml)

```yaml
server:
  mode: oauth
  secrets:
    mode: kubernetes
    kubernetes:
      namespace: scia
  users:
    alice:
      secretName: scia-oauth-alice
  oauth:
    redirectUrl: "http://localhost:18081/oauth/google/callback"
    google:
      credentialId: google-calendar
      clientId: "env:GOOGLE_OAUTH_CLIENT_ID"
      clientSecret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      scope: "https://www.googleapis.com/auth/calendar.readonly"
```

Create the Google OAuth client Secret yourself:

```sh
kubectl create secret generic scia-google-oauth \
  -n scia \
  --from-literal=client-id='YOUR_GOOGLE_OAUTH_CLIENT_ID' \
  --from-literal=client-secret='YOUR_GOOGLE_OAUTH_CLIENT_SECRET'
```

Register this redirect URI on the Google OAuth client:

```text
http://localhost:18081/oauth/google/callback
```

For local browser authorization, forward the OAuth service:

```sh
kubectl port-forward -n scia svc/scia-oauth 18081:8081
```

Open:

```text
http://localhost:18081/
```

In kubernetes mode, each user gets their own authorize button. After authorization,
`scia` stores the Google refresh token in that user's Kubernetes Secret under the
`refresh_token` key.

## Proxy server

Example config: [configs/proxy-kubernetes.yaml](../configs/proxy-kubernetes.yaml)

User-to-secret mapping is managed in each proxy deployment's config. Credentials
reference the shared Google OAuth client from `server.oauth.google` and declare which
user's Secret to read:

```yaml
server:
  mode: proxy
  secrets:
    mode: kubernetes
    kubernetes:
      namespace: scia
  users:
    alice:
      secretName: scia-oauth-alice
  oauth:
    google:
      credentialId: google-calendar
      clientId: "env:GOOGLE_OAUTH_CLIENT_ID"
      clientSecret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      scope: "https://www.googleapis.com/auth/calendar.readonly"

credentials:
  - id: google-calendar
    type: google-oauth-refresh-token
    params:
      user: alice

rules:
  - name: inject-alice-google-calendar-token
    hosts: ["www.googleapis.com"]
    paths: ["/calendar/v3/*"]
    action: allow
    credentials: ["google-calendar"]
```

For a quick proxy test, also forward the proxy service:

```sh
kubectl port-forward -n scia svc/scia-proxy 18080:8080
curl --noproxy '' -x http://localhost:18080 \
  https://www.googleapis.com/calendar/v3/users/me/calendarList
```

## Integration tests

Run the envtest-based Kubernetes integration tests with:

```sh
export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use -p path 1.29.0!)"
SCIA_K8S_INTEGRATION=1 go test ./internal/secrets -run Kubernetes -count=1 -v
```

These tests cover Secret create/update, OAuth callback persistence, and proxy token
injection against a real Kubernetes API server.
