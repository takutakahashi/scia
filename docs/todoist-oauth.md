# Todoist OAuth Setup

`scia` can store Todoist OAuth tokens and inject them into requests to
`api.todoist.com`. Use this when an agent should call Todoist without receiving
the Todoist OAuth client secret or long-lived user tokens directly.

## Todoist app

Create a Todoist app in the Todoist App Management Console:

https://app.todoist.com/appconsole

Configure at least one OAuth redirect URL. For local setup with the default
`scia` OAuth helper, use:

```text
http://localhost:8081/oauth/todoist/callback
```

Copy the Todoist `Client ID` and `Client Secret`. The examples below read them
from environment variables:

```sh
export TODOIST_OAUTH_CLIENT_ID="..."
export TODOIST_OAUTH_CLIENT_SECRET="..."
```

Todoist scopes are comma-separated. Common choices are:

- `task:add` for adding tasks without reading existing data.
- `data:read` for read-only access to tasks, projects, labels, and filters.
- `data:read_write` for read/write access. This includes `task:add` and
  `data:read`.
- `data:delete` for deleting tasks, labels, and filters.
- `project:delete` for deleting projects.

## Local OAuth helper

Create a helper config such as `configs/todoist-oauth.yaml`. Add a Todoist
OAuth client under `server.oauth.todoist` and set `server.mode` to `oauth`:

```yaml
server:
  mode: "oauth"
  oauth:
    listen: "127.0.0.1:8081"
    todoist:
      credentialId: todoist
      clientId: "env:TODOIST_OAUTH_CLIENT_ID"
      clientSecret: "env:TODOIST_OAUTH_CLIENT_SECRET"
      scope: "data:read_write"
      redirectUrl: "http://localhost:8081/oauth/todoist/callback"

credentials:
  - id: todoist
    type: todoist-oauth-refresh-token
    params: {}
```

Start the OAuth helper with that config:

```sh
go run ./cmd/scia -config configs/todoist-oauth.yaml
```

Open the helper UI:

```text
http://localhost:8081/
```

Choose the Todoist credential and approve the Todoist consent screen. `scia`
stores the returned token in the configured secret store under the credential ID
`todoist`.

New Todoist apps issue one-hour access tokens and a refresh token. Todoist
rotates refresh tokens on every refresh, and `scia` stores the replacement
refresh token automatically. Legacy Todoist apps may return a long-lived
`access_token` without a `refresh_token`; `scia` stores that access token and
uses it directly.

## Proxy credential injection

Create a proxy config such as `configs/todoist-proxy.yaml`. Add a rule that
applies the Todoist credential to Todoist API requests and set `server.mode` to
`proxy`:

```yaml
server:
  mode: "proxy"

rules:
  - name: inject-todoist-token
    hosts: ["api.todoist.com"]
    paths: ["/api/v1/*"]
    action: allow
    credentials: ["todoist"]
```

Run the proxy with that config:

```sh
go run ./cmd/scia -config configs/todoist-proxy.yaml -listen :8080
```

Configure the agent or HTTP client to use `http://127.0.0.1:8080` as its proxy.
Matching requests to `https://api.todoist.com/api/v1/...` receive:

```text
Authorization: Bearer <todoist-access-token>
```

## Namespaced broker

Use `server.oauth.namespaces` when one OAuth service should hold the Todoist
client secret and another proxy service should only request access tokens.

OAuth broker config:

```yaml
server:
  mode: "oauth"
  oauth:
    listen: "127.0.0.1:8081"
    brokerToken: "env:SCIA_OAUTH_BROKER_TOKEN"
    namespaces:
      service-a:
        todoist:
          clientIdSecretRef: "secret:service-a.todoist.client-id"
          clientSecretRef: "secret:service-a.todoist.client-secret"
          scope: "data:read_write"
          redirectUrl: "https://service-a.example.com/oauth/todoist/callback"
```

The broker exposes these endpoints:

- `GET /oauth/{namespace}/todoist/authorization-url?state=...`
- `GET /oauth/{namespace}/todoist/start`
- `POST /oauth/{namespace}/todoist/token`
- `POST /oauth/{namespace}/todoist/access-token`
- `POST /oauth/{namespace}/todoist/revoke`

When `server.oauth.brokerToken` is set, calls to `authorization-url`, `token`,
`access-token`, and `revoke` require:

```text
Authorization: Bearer <SCIA_OAUTH_BROKER_TOKEN>
```

Proxy config using the broker:

```yaml
credentials:
  - id: service-a.todoist
    type: todoist-oauth-refresh-token
    params:
      token_broker_url: "http://scia-oauth:8081/oauth/service-a/todoist/token"
      token_broker_token: "env:SCIA_OAUTH_BROKER_TOKEN"

rules:
  - name: inject-service-a-todoist-token
    hosts: ["api.todoist.com"]
    paths: ["/api/v1/*"]
    action: allow
    credentials: ["service-a.todoist"]
```

## Troubleshooting

- `invalid_request` on the Todoist consent screen usually means the app has
  multiple redirect URLs configured and the request did not include a matching
  `redirect_uri`. Set `server.oauth.todoist.redirectUrl` or
  `server.oauth.namespaces.<namespace>.todoist.redirectUrl`.
- `invalid_scope` means the `scope` value is not supported by Todoist. Use a
  comma-separated Todoist scope string such as `data:read_write`.
- `refresh_token or access_token is not registered` means the Todoist OAuth
  callback has not been completed for that credential, or the configured secret
  store does not contain the token.
- `invalid_grant` from Todoist during refresh means the refresh token is
  unknown, revoked, expired, or was reused outside Todoist's retry grace window.
  Re-authorize the Todoist credential through the helper UI.
