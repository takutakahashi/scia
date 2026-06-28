# scia

SaaS credential injector for agents.

`scia` is a Go forward proxy that lets agents call upstream APIs without storing shared OAuth clients, API keys, or long-lived tokens locally. It loads policy and credential configuration, injects authentication headers into outbound requests, and can deny or hold sensitive requests until an operator approves them.

## Features

- Forward proxy for HTTP and HTTPS requests with credential injection.
- Credential types: bearer token, basic auth, static header, OAuth2 client credentials, Google OAuth refresh tokens, Notion OAuth refresh tokens, Todoist OAuth refresh tokens, and Slack OAuth user tokens.
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
- `GET /_scia/credentials/status`
- `POST /_scia/tokens`
- `POST /_scia/tokens/revoke`
- `POST /_scia/approvals/{id}/approve`
- `POST /_scia/approvals/{id}/deny`

If `server.adminToken` is set, admin requests must include `Authorization: Bearer <token>`. Config values with the `env:` prefix are read from environment variables.

`GET /_scia/credentials/status` returns configured credentials with an
`authenticated` flag. Token values are not returned:

```sh
curl http://localhost:8080/_scia/credentials/status \
  -H "Authorization: Bearer $SCIA_ADMIN_TOKEN"
```

`POST /_scia/tokens` stores a token in the configured secret store and returns
`204 No Content` without echoing the token value:

```sh
curl -X POST http://localhost:8080/_scia/tokens \
  -H "Authorization: Bearer $SCIA_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credentialId":"github","key":"access_token","token":"TOKEN_VALUE"}'
```

The same request can include provider-derived service metadata. `scia` stores it
beside the token in the secret store and indexes the service ID. After that, the
proxy can match requests against the stored service hosts without defining
`server.services.<id>` or `rules[].services` in proxy config:

```yaml
server:
  adminToken: "env:SCIA_ADMIN_TOKEN"
  secrets:
    sqlitePath: "data/scia-proxy-secrets.db"
```

```sh
curl -X POST http://localhost:8080/_scia/tokens \
  -H "Authorization: Bearer $SCIA_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "credentialId": "mock-dex-api",
    "key": "access_token",
    "token": "TOKEN_VALUE",
    "service": {
      "hosts": [{"host": "api.example.com", "authMethod": "bearer"}],
      "oauth": {
        "authUrl": "https://issuer.example.com/auth",
        "tokenUrl": "https://issuer.example.com/token"
      },
      "injection": {
        "headers": [{"name": "Authorization", "value": "Bearer {{ .access_token }}"}]
      }
    }
  }'
```

If a proxy has neither `server.services.<id>` nor stored service metadata, it can
fetch the metadata from the OAuth helper server and cache it in its own secret
store when a rule names the service. Configure the proxy with the OAuth helper
metadata endpoint:

```yaml
server:
  oauth:
    metadataUrl: "http://localhost:8081/api/services"
    metadataToken: "env:SCIA_ADMIN_TOKEN"
rules:
  - name: inject-dex
    hosts: ["api.example.com"]
    action: allow
    services: ["mock-dex-api"]
```

The OAuth helper serves `GET /api/services/{service}` and
`GET /api/services/{service}/metadata`. If `server.adminToken` is set on the
OAuth helper, callers must send `Authorization: Bearer <token>`.

`POST /_scia/tokens/revoke` revokes a stored token through a configured broker
and deletes the local secret only after the broker succeeds. Configure the
credential with `params.revoke_broker_url`; `params.revoke_broker_token` is sent
as a bearer token when present, and falls back to `params.token_broker_token`.

```sh
curl -X POST http://localhost:8080/_scia/tokens/revoke \
  -H "Authorization: Bearer $SCIA_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credentialId":"github","key":"access_token"}'
```

The revoke broker receives `application/x-www-form-urlencoded` fields:
`credential_id`, `credential_type`, `token`, and `token_type_hint`.

The OAuth helper UI runs on a separate port, `server.oauth.listen` (`127.0.0.1:8081` by default). Configure the Google OAuth client redirect URI to match `server.oauth.redirectUrl`, for example:

```yaml
server:
  oauth:
    listen: "127.0.0.1:8081"
    redirectUrl: "http://localhost:8081/oauth/google/callback"
    google:
      credentialId: google-calendar
      clientId: "env:GOOGLE_OAUTH_CLIENT_ID"
      clientSecret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      scope: "https://www.googleapis.com/auth/calendar"
```

Open `http://localhost:8081/` to start Google authorization for configured Google credentials.

Notion public connections use the same helper UI. Configure the Notion public
connection redirect URI to match `server.oauth.notion.redirectUrl`, for example:

```yaml
server:
  oauth:
    notion:
      credentialId: notion-workspace
      clientId: "env:NOTION_OAUTH_CLIENT_ID"
      clientSecret: "env:NOTION_OAUTH_CLIENT_SECRET"
      redirectUrl: "http://localhost:8081/oauth/notion/callback"
      notionVersion: "2026-03-11"
```

Open `http://localhost:8081/` and choose the Notion credential. `scia` sends
the authorization request to Notion with `owner=user`, exchanges the returned
code with JSON + HTTP Basic authentication, and stores the resulting
`refresh_token`.

Todoist apps use the same helper UI. Configure the Todoist app redirect URI to
match `server.oauth.todoist.redirectUrl`, for example:

```yaml
server:
  oauth:
    todoist:
      credentialId: todoist
      clientId: "env:TODOIST_OAUTH_CLIENT_ID"
      clientSecret: "env:TODOIST_OAUTH_CLIENT_SECRET"
      scope: "data:read_write"
      redirectUrl: "http://localhost:8081/oauth/todoist/callback"
```

Open `http://localhost:8081/` and choose the Todoist credential. `scia` sends
the authorization request to Todoist, exchanges the returned code at
`https://api.todoist.com/oauth/access_token`, and stores the returned
`refresh_token`. Legacy Todoist apps that do not issue refresh tokens store the
long-lived `access_token` instead.

See [docs/todoist-oauth.md](docs/todoist-oauth.md) for the full Todoist setup
guide, including local helper setup and proxy injection.

OAuth callback refresh tokens are stored in the SQLite secret store by default:

```yaml
server:
  secrets:
    sqlitePath: "data/scia-secrets.db"
```

To send secrets to an external system instead, use the `external` secret store:

```yaml
server:
  secrets:
    mode: "external"
    external:
      webhook:
        url: "env:SCIA_EXTERNAL_SECRETS_WEBHOOK_URL"
        secretKey: "env:SCIA_EXTERNAL_SECRETS_WEBHOOK_SECRET_KEY"
```

`external` posts a JSON webhook on `Put` and `Delete`. Secret values are sent in
the payload as AES-256-GCM encrypted `value.ciphertext`; `credential_id`, `key`,
event type, and timestamp are sent as plaintext metadata. The AES key is derived
from `secretKey` with SHA-256, and the GCM additional authenticated data is
`credential_id + "\x00" + key`.

The SQLite file stores values by credential ID and key. For Google credentials,
callback stores `refresh_token`; request-time injection reads
`params.refresh_token` first and falls back to the secret store. For Notion
credentials, request-time injection prefers the secret store because Notion
refreshes return a new `refresh_token`, which `scia` stores for the next
refresh.
For Todoist credentials, request-time injection uses a stored `access_token`
when present, otherwise refreshes with a stored `refresh_token` and stores any
rotated refresh token returned by Todoist.

Slack apps use the same helper UI for user-centric OAuth. Configure the Slack
app redirect URI to match `server.oauth.slack.redirectUrl`, for example:

```yaml
server:
  oauth:
    slack:
      credentialId: slack
      clientId: "env:SLACK_OAUTH_CLIENT_ID"
      clientSecret: "env:SLACK_OAUTH_CLIENT_SECRET"
      scope: "users:read chat:write"
      redirectUrl: "http://localhost:8081/oauth/slack/callback"
```

Open `http://localhost:8081/` and choose the Slack credential. `scia` sends the
authorization request to Slack's user-token authorization endpoint, exchanges
the returned code at `https://slack.com/api/oauth.v2.user.access`, and stores a
returned `refresh_token` when token rotation is enabled. If Slack returns only a
long-lived user `access_token`, that token is stored instead. Request-time
injection uses a stored `access_token` when present, otherwise refreshes with the
stored `refresh_token` at `https://slack.com/api/oauth.v2.access`.

GitHub OAuth Apps use the same helper UI. Configure the GitHub OAuth App
callback URL to match `server.oauth.github.redirectUrl`, for example:

```yaml
server:
  oauth:
    github:
      credentialId: github
      clientId: "env:GITHUB_OAUTH_CLIENT_ID"
      clientSecret: "env:GITHUB_OAUTH_CLIENT_SECRET"
      scope: "repo read:user"
      redirectUrl: "http://localhost:8081/oauth/github/callback"
```

Open `http://localhost:8081/` and choose the GitHub credential. `scia` sends
the authorization request to `https://github.com/login/oauth/authorize`,
exchanges the returned code at `https://github.com/login/oauth/access_token`,
and stores the returned `access_token`.

The SQLite store is local persistence, not encryption. Keep the database path on a protected volume and restrict filesystem access to the `scia` process.

## Frontend integration metadata

- `GET /api/integrations` returns configured OAuth integrations as JSON for a frontend.
- The response is generated from the current config on every request, so config reloads are reflected without frontend changes.
- Secrets and raw OAuth scope values are not returned. The response includes provider IDs, display metadata, setup URLs such as callback/auth/token/revoke URLs, start endpoints, and scope display metadata.
- `server.oauth.integrations.<provider-or-credential-id>.released: false` can be used to configure an integration before exposing it in the frontend.
- `scopes[].enabled` means the scope is selected by default. Frontends can pass a `scope` query parameter containing `scopes[].id` values to OAuth `start` or `authorization-url` endpoints to authorize a different subset.
- When integration metadata scopes are configured, requested scopes must match `scopes[].id`; unknown scopes are rejected with `400 Bad Request`. Raw `value` strings are accepted for backward compatibility but do not need to be exposed to frontends.

Example:

```yaml
server:
  oauth:
    integrations:
      google-calendar:
        name: "Google Calendar"
        iconUrl: "https://www.gstatic.com/images/branding/product/1x/calendar_2020q4_48dp.png"
        description: "Connect Google Calendar to read and update calendar events."
        released: false
        setup:
          callback_url: "https://scia.example.com/oauth/google/callback"
        scopes:
          - id: "calendar-write"
            value: "https://www.googleapis.com/auth/calendar"
            name: "Calendar read/write"
            desc: "Read, create, and update events."
            enabled: true
          - id: "calendar-read"
            value: "https://www.googleapis.com/auth/calendar.readonly"
            name: "Calendar read-only"
            desc: "Read events without writing changes."
            enabled: false
```

## Configuration

See [configs/example.yaml](configs/example.yaml).

Rules are evaluated in order. If no rule matches, the request is allowed without credential injection.

Google OAuth client credentials can be configured once under `server.oauth.google`. The OAuth helper UI stores the resulting refresh token in SQLite under `credentialId`, and rules can reference that credential ID:

```yaml
server:
  oauth:
    google:
      credentialId: google-calendar
      clientId: "env:GOOGLE_OAUTH_CLIENT_ID"
      clientSecret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      scope: "https://www.googleapis.com/auth/calendar"

credentials:
  - id: google-calendar
    type: google-oauth-refresh-token
    params: {}

rules:
  - name: inject-google-calendar-token
    hosts: ["www.googleapis.com"]
    paths: ["/calendar/v3/*"]
    action: allow
    credentials: ["google-calendar"]
```

The `credentials` entry is optional when `server.oauth.google.credentialId` is configured; it is useful when you want to override per-credential params such as `scope`, `token_url`, or `refresh_token`. `scia` exchanges the refresh token at `https://oauth2.googleapis.com/token`, caches the returned access token until it is close to expiry, and injects it as `Authorization: Bearer <access_token>` only for matching rules.

Notion OAuth client credentials can be configured once under
`server.oauth.notion`. The `credentials` entry is optional when
`server.oauth.notion.credentialId` is configured:

```yaml
server:
  oauth:
    notion:
      credentialId: notion-workspace
      clientId: "env:NOTION_OAUTH_CLIENT_ID"
      clientSecret: "env:NOTION_OAUTH_CLIENT_SECRET"
      redirectUrl: "http://localhost:8081/oauth/notion/callback"

credentials:
  - id: notion-workspace
    type: notion-oauth-refresh-token
    params: {}

rules:
  - name: inject-notion-token
    hosts: ["api.notion.com"]
    paths: ["/v1/*"]
    action: allow
    credentials: ["notion-workspace"]
```

`scia` exchanges Notion refresh tokens at
`https://api.notion.com/v1/oauth/token`, caches the returned access token, stores
rotated refresh tokens, and injects `Authorization: Bearer <access_token>` plus a
default `Notion-Version: 2026-03-11` header for matching rules.

Todoist OAuth client credentials can be configured once under
`server.oauth.todoist`. The `credentials` entry is optional when
`server.oauth.todoist.credentialId` is configured:

```yaml
server:
  oauth:
    todoist:
      credentialId: todoist
      clientId: "env:TODOIST_OAUTH_CLIENT_ID"
      clientSecret: "env:TODOIST_OAUTH_CLIENT_SECRET"
      scope: "data:read_write"

credentials:
  - id: todoist
    type: todoist-oauth-refresh-token
    params: {}

rules:
  - name: inject-todoist-token
    hosts: ["api.todoist.com"]
    paths: ["/api/v1/*"]
    action: allow
    credentials: ["todoist"]
```

`scia` exchanges Todoist refresh tokens at
`https://api.todoist.com/oauth/access_token`, caches the returned access token,
stores rotated refresh tokens, and injects
`Authorization: Bearer <access_token>` for matching rules.

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
