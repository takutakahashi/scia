# scia

SaaS credential injector for agents.

`scia` is a Go forward proxy that lets agents call upstream APIs without storing shared OAuth clients, API keys, or long-lived tokens locally. It loads policy and credential configuration, injects authentication headers into outbound requests, and can deny or hold sensitive requests until an operator approves them.

## Features

- Forward proxy for HTTP and HTTPS requests with credential injection.
- Credential types: bearer token, basic auth, static header, OAuth2 client credentials, and Google OAuth refresh tokens.
- Policy rules by host, method, and path with `allow`, `deny`, or `approval` actions.
- Blocking approval flow exposed through local admin endpoints.
- Reloadable configuration through a provider interface. The first adapter is YAML from the filesystem; database and AWS Secrets Manager providers can be added behind the same `config.Provider` interface.
- Optional backend proxy chaining for outbound traffic from `scia` to upstream services.
- Container image and GitHub Actions release flow managed by semantic version tags.

## HTTPS interception

For HTTPS forward proxy traffic, clients use `CONNECT`. `scia` handles `CONNECT` by default with local TLS interception: it creates or loads a local CA, dynamically signs a leaf certificate for the requested host, terminates TLS from the agent, applies path/method/header policy and credential injection, then opens a new HTTPS request to the upstream.

Agents must trust the scia CA certificate. The current CA is available at:

- `GET /_scia/ca.pem`

By default the CA files are stored at `data/scia-ca.pem` and `data/scia-ca-key.pem`. Override these with `server.mitm.caCertPath` and `server.mitm.caKeyPath`.

Clients that pin upstream certificates may reject intercepted HTTPS connections. Prefer trusting the scia CA only inside the agent runtime, not system-wide on an operator machine.

## Backend proxy chaining

Set `server.backendProxy.url` to route outbound requests from `scia` through another proxy:

```yaml
server:
  backendProxy:
    url: "http://proxy.internal:3128"
```

Values with the `env:` prefix are expanded, so `env:SCIA_BACKEND_PROXY_URL` can be used for deployment-specific proxy URLs. The backend proxy is applied after policy evaluation and credential injection, including HTTPS requests that `scia` intercepts from client `CONNECT` traffic.

## Run locally

```sh
go run ./cmd/scia -config configs/example.yaml -listen :8080
```

Configure an HTTP client to use `http://127.0.0.1:8080` as its proxy.

Admin endpoints:

- `GET /_scia/healthz`
- `GET /_scia/ca.pem`
- `GET /_scia/approvals`
- `POST /_scia/approvals/{id}/approve`
- `POST /_scia/approvals/{id}/deny`

If `server.adminToken` is set, admin requests must include `Authorization: Bearer <token>`. Config values with the `env:` prefix are read from environment variables.

The OAuth helper UI runs on a separate port, `server.oauth.listen` (`127.0.0.1:8081` by default). Configure the Google OAuth client redirect URI to match `server.oauth.redirectUrl`, for example:

```yaml
server:
  oauth:
    listen: "127.0.0.1:8081"
    redirectUrl: "http://localhost:8081/oauth/google/callback"
```

Open `http://localhost:8081/` to start Google authorization for configured Google credentials.

## Configuration

See [configs/example.yaml](configs/example.yaml).

Rules are evaluated in order. If no rule matches, the request is allowed without credential injection.

Google OAuth client credentials can be configured with a pre-issued refresh token:

```yaml
credentials:
  - id: google-calendar
    type: google-oauth-refresh-token
    params:
      client_id: "env:GOOGLE_OAUTH_CLIENT_ID"
      client_secret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      refresh_token: "env:GOOGLE_OAUTH_REFRESH_TOKEN"
      scope: "https://www.googleapis.com/auth/calendar"

rules:
  - name: inject-google-calendar-token
    hosts: ["www.googleapis.com"]
    paths: ["/calendar/v3/*"]
    action: allow
    credentials: ["google-calendar"]
```

`scia` exchanges the refresh token at `https://oauth2.googleapis.com/token`, caches the returned access token until it is close to expiry, and injects it as `Authorization: Bearer <access_token>` only for matching rules.

## Build

```sh
make test
make build
make image
```

The Docker image defaults to `ghcr.io/takutakahashi/scia:<VERSION>`.

## Release

Releases use semantic versioning. Update [VERSION](VERSION), create a matching tag with a `v` prefix, and push it:

```sh
printf "0.2.0\n" > VERSION
git commit -am "chore: release 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

The release workflow runs GoReleaser, publishes GitHub release artifacts, and pushes multi-architecture container images to GHCR.

See [docs/release.md](docs/release.md) for the release checklist.
