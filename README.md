# scia

SaaS credential injector for agents.

`scia` is a Go forward proxy that lets agents call upstream APIs without storing shared OAuth clients, API keys, or long-lived tokens locally. It loads policy and credential configuration, injects authentication headers into outbound requests, and can deny or hold sensitive requests until an operator approves them.

## Features

- Forward proxy for HTTP and HTTPS requests with credential injection.
- Credential types: bearer token, basic auth, static header, OAuth2 client credentials, Google OAuth refresh tokens, and Notion OAuth refresh tokens.
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

Slack apps use the same helper UI. Configure bot scopes with `scope`, user
scopes with `userScope`, and set `tokenType: "user"` to store the Slack
`authed_user.access_token` as the credential access token:

```yaml
server:
  oauth:
    slack:
      credentialId: slack-user
      clientId: "env:SLACK_OAUTH_CLIENT_ID"
      clientSecret: "env:SLACK_OAUTH_CLIENT_SECRET"
      userScope: "chat:write users:read"
      tokenType: "user"
      redirectUrl: "http://localhost:8081/oauth/slack/callback"
```

Open `http://localhost:8081/` and choose the Slack credential. `scia` exchanges
the returned code with Slack `oauth.v2.access` and stores the selected
`access_token`.

OAuth callback refresh tokens are stored in the SQLite secret store by default:

```yaml
server:
  secrets:
    sqlitePath: "data/scia-secrets.db"
```

The SQLite file stores values by credential ID and key. For Google credentials,
callback stores `refresh_token`; request-time injection reads
`params.refresh_token` first and falls back to the secret store. For Notion
credentials, request-time injection prefers the secret store because Notion
refreshes return a new `refresh_token`, which `scia` stores for the next
refresh. For Slack credentials, callback stores `access_token`; if Slack returns
a rotated `refresh_token`, that value is stored too.

The SQLite store is local persistence, not encryption. Keep the database path on a protected volume and restrict filesystem access to the `scia` process.

## Namespaced OAuth broker

`server.oauth.namespaces` configures OAuth clients by namespace. This lets agents or a proxy call scia for authorization URLs, token refresh, and revocation without receiving the SaaS client ID or client secret.

```yaml
server:
  mode: "oauth"
  oauth:
    listen: "127.0.0.1:8081"
    brokerToken: "env:SCIA_OAUTH_BROKER_TOKEN"
    namespaces:
      service-a:
        google:
          clientIdSecretRef: "secret:service-a.google.client-id"
          clientSecretRef: "secret:service-a.google.client-secret"
          scope: "https://www.googleapis.com/auth/calendar"
          redirectUrl: "https://service-a.example.com/oauth/callback"
        notion:
          clientIdSecretRef: "secret:service-a.notion.client-id"
          clientSecretRef: "secret:service-a.notion.client-secret"
          redirectUrl: "https://service-a.example.com/oauth/notion/callback"
        slack:
          clientIdSecretRef: "secret:service-a.slack.client-id"
          clientSecretRef: "secret:service-a.slack.client-secret"
          userScope: "chat:write users:read"
          tokenType: "user"
          redirectUrl: "https://service-a.example.com/oauth/slack/callback"
```

`server.mode` is exclusive:

- `proxy` starts only the forward proxy.
- `oauth` starts only the OAuth broker server.

The two servers are not started in the same process.

Secret refs support these forms:

- `secret:namespace.provider.key` resolves from the configured secret store as credential ID `namespace.provider` and key `key`.
- `namespace.provider.key` is accepted as a shorthand for `secret:namespace.provider.key`.
- `env:NAME` resolves from the process environment, which is useful for local experiments.

For the example above, store `client-id` and `client-secret` under credential ID `service-a.google`. For env-backed experiments, use:

```yaml
clientIdSecretRef: "env:SERVICE_A_GOOGLE_CLIENT_ID"
clientSecretRef: "env:SERVICE_A_GOOGLE_CLIENT_SECRET"
```

Google broker endpoints:

- `GET /oauth/{namespace}/google/authorization-url?state=...` returns a generated Google authorization URL.
- `GET /oauth/{namespace}/google/start` redirects to the generated Google authorization URL.
- `POST /oauth/{namespace}/google/token` forwards a refresh-token or authorization-code request to Google with the configured client ID and client secret injected by scia.
- `POST /oauth/{namespace}/google/access-token` exchanges the refresh token stored by scia for a Google access token.
- `POST /oauth/{namespace}/google/revoke` forwards a revoke request to Google.

Notion broker endpoints:

- `GET /oauth/{namespace}/notion/authorization-url?state=...` returns a generated Notion authorization URL.
- `GET /oauth/{namespace}/notion/start` redirects to the generated Notion authorization URL.
- `POST /oauth/{namespace}/notion/token` forwards a refresh-token or authorization-code request to Notion with the configured client ID and client secret injected by scia.
- `POST /oauth/{namespace}/notion/access-token` exchanges the refresh token stored by scia for a Notion access token and stores any rotated refresh token returned by Notion.
- `POST /oauth/{namespace}/notion/revoke` forwards a revoke request to Notion.

Slack broker endpoints:

- `GET /oauth/{namespace}/slack/authorization-url?state=...` returns a generated Slack authorization URL.
- `GET /oauth/{namespace}/slack/start` redirects to the generated Slack authorization URL.
- `POST /oauth/{namespace}/slack/token` forwards an authorization-code or refresh-token request to Slack with the configured client ID and client secret injected by scia.
- `POST /oauth/{namespace}/slack/access-token` returns the Slack access token stored by scia.
- `POST /oauth/{namespace}/slack/revoke` forwards a revoke request to Slack.

Slack OAuth supports bot and user tokens. Configure bot scopes with `scope`,
user scopes with `userScope`, and set `tokenType: "user"` when the proxy should
inject the `authed_user.access_token` returned by Slack. This follows Slack's
OAuth v2 response shape, where user tokens are returned under `authed_user` when
user scopes are requested.

When `server.oauth.brokerToken` is set, broker API requests to
`authorization-url`, `token`, `access-token`, and `revoke` must include
`Authorization: Bearer <token>`. `env:` values are expanded, so the OAuth server
and proxy can share a Kubernetes Secret or deployment environment variable
without putting the token in config files. The browser redirect endpoint
`/oauth/{namespace}/{provider}/start` is not protected by this header because
browsers do not attach service-to-service bearer tokens during redirects.

The proxy can also reference the namespaced Google credential ID directly:

```yaml
rules:
  - name: inject-service-a-google-token
    hosts: ["www.googleapis.com"]
    paths: ["/calendar/v3/*"]
    action: allow
    credentials: ["service-a.google"]
```

For a proxy that should not read OAuth client secrets directly, configure the
Google credential with `params.token_broker_url`. The proxy reads the refresh
token from its configured secret store, POSTs it to the OAuth broker when a
matching request needs an access token, caches the returned access token until
expiry, and injects it into the upstream request:

```yaml
credentials:
  - id: service-a.google
    type: google-oauth-refresh-token
    params:
      token_broker_url: "http://scia-oauth:8081/oauth/service-a/google/token"
      token_broker_token: "env:SCIA_OAUTH_BROKER_TOKEN"
  - id: service-a.notion
    type: notion-oauth-refresh-token
    params:
      token_broker_url: "http://scia-oauth:8081/oauth/service-a/notion/token"
      token_broker_token: "env:SCIA_OAUTH_BROKER_TOKEN"
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
