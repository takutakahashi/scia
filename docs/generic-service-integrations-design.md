# Generic Service Integrations Design

## Goal

Introduce a generic service integration mechanism so `scia` can connect arbitrary services without adding a new Go credential type and OAuth handler for every provider.

The mechanism should cover the pattern used by OneCLI's app provider registry:

- match outbound requests by host and path
- resolve a provider-specific credential
- refresh or use a token when needed
- inject authentication as headers, query parameters, or Basic auth
- expose OAuth start/callback metadata to the helper UI

## Findings

`scia` currently has provider-specific structs and branches:

- `server.integrations` has fixed fields for `google`, `notion`, `todoist`, `slack`, and `github`
- `server.oauth` has fixed provider structs for the same providers
- `CredentialByID` synthesizes fixed credential types from configured OAuth clients
- `auth.Injector.applyOne` switches on credential type, including provider-specific refresh-token types
- `oauth.Server.Handler` registers fixed `/oauth/{provider}/start` and `/oauth/{provider}/callback` routes

This works for the current providers, but adding a service requires touching config, validation, OAuth server routes, token exchange, credential injection, MITM host selection, docs, and tests.

OneCLI centralizes most of this as an app provider definition in `apps/gateway/src/apps.rs`. The important model is:

- `AppProvider`: provider slug, display name, host rules, refresh config, metadata/credential header mappings, query param mappings, optional host rewrite, optional request finalizer
- `HostRule`: exact/suffix host match, optional path prefix, auth strategy, optional host-gated credential field
- `AuthStrategy`: bearer token, GitHub-style basic `x-access-token:{token}`, or no Authorization header
- `RefreshConfig`: token URL, client ID/secret source, form vs JSON token body, body vs Basic client authentication

`scia` should adopt the same concepts, but make them YAML-driven instead of a compiled static registry.

## Proposed Config Shape

Add `server.services` as the canonical registry for generic service integrations.

```yaml
server:
  services:
    github:
      name: GitHub
      hosts:
        - host: api.github.com
          authMethod: bearer
        - host: github.com
          authMethod: basic-x-access-token
      oauth:
        credentialId: github
        clientId: env:GITHUB_OAUTH_CLIENT_ID
        clientSecret: env:GITHUB_OAUTH_CLIENT_SECRET
        authUrl: https://github.com/login/oauth/authorize
        tokenUrl: https://github.com/login/oauth/access_token
        revokeUrl: https://api.github.com/applications
        scopeParam:
          name: scope
          separator: " "
        tokenRequest:
          bodyFormat: form
          clientAuth: body
      injection:
        headers:
          - name: Authorization
            value: "Bearer {{ .access_token }}"
```

For non-OAuth services:

```yaml
server:
  services:
    datadog:
      name: Datadog
      hosts:
        - host: api.datadoghq.com
          authMethod: none
      injection:
        headers:
          - name: DD-API-KEY
            value: "{{ secret \"api_key\" }}"
          - name: DD-APPLICATION-KEY
            value: "{{ secret \"application_key\" }}"
```

For query parameter auth:

```yaml
server:
  services:
    trello:
      name: Trello
      hosts:
        - host: api.trello.com
          authMethod: none
      injection:
        query:
          - name: key
            value: "{{ secret \"key\" }}"
          - name: token
            value: "{{ secret \"token\" }}"
```

Rules should be able to reference the service directly:

```yaml
rules:
  - name: inject-github
    hosts: ["api.github.com"]
    action: allow
    services: ["github"]
```

During migration, keep `credentials` supported and allow either `credentials` or `services` on a rule. Internally both should resolve to injection plans.

## Config Types

Add these structs, names subject to final code review:

```go
type ServicesConfig map[string]ServiceConfig

type ServiceConfig struct {
    Name        string
    IconURL     string
    Description string
    Released    *bool
    Hosts       []ServiceHostRule
    OAuth       *ServiceOAuthConfig
    Injection   ServiceInjectionConfig
}

type ServiceHostRule struct {
    Host       string
    HostSuffix string
    PathPrefix string
    AuthMethod string // bearer, basic-x-access-token, basic, none
    CredentialHostField string
}

type ServiceOAuthConfig struct {
    CredentialID      string
    ClientID          string
    ClientIDSecretRef string
    ClientSecret      string
    ClientSecretRef   string
    AuthURL           string
    TokenURL          string
    RevokeURL         string
    RedirectURL       string
    ScopeParam        ScopeParamConfig
    TokenRequest      TokenRequestConfig
}

type ScopeParamConfig struct {
    Name      string // usually "scope"; empty disables scope query param
    Separator string // usually " "; sometimes "," depending on provider
}

type TokenRequestConfig struct {
    BodyFormat string // form, json
    ClientAuth string // body, basic
}

type ServiceInjectionConfig struct {
    Headers []InjectionTemplate
    Query   []InjectionTemplate
}

type InjectionTemplate struct {
    Name  string
    Value string
}
```

Validation rules:

- service ID must be non-empty, unique, and URL/path safe
- each service must have at least one host rule
- each host rule must use exactly one of `host` or `hostSuffix`
- `authMethod` defaults to `bearer` when OAuth is configured, otherwise `none`
- OAuth services must define `clientId`, `clientSecret`, `authUrl`, and `tokenUrl` directly or via secret refs
- `scopeParam.name` defaults to `scope`; set it to an empty string only for providers that do not accept a scope parameter
- `scopeParam.separator` defaults to a single space because most OAuth servers expect space-delimited scope values
- `tokenRequest.bodyFormat` defaults to `form`
- `tokenRequest.clientAuth` defaults to `body`
- reject templated header/query values that reference unsupported fields
- reject ambiguous host rules where a catch-all and path-scoped rule share the same host for one service unless explicitly ordered

## Multiple YAML Files

`scia` should support loading more than one YAML file and merging them in order. This lets the container image ship default service definitions while operators keep local secrets, rules, and overrides in a separate file.

CLI proposal:

```sh
scia \
  -config /etc/scia/services/google.yaml \
  -config /etc/scia/services/github.yaml \
  -config /etc/scia/scia.yaml
```

Semantics:

- `-config` becomes repeatable. A single `-config` keeps today's behavior.
- files are loaded left to right
- later files override earlier scalar/map values
- maps such as `server.services` merge by key
- slices such as `rules`, `credentials`, `hosts`, `headers`, and `query` replace the earlier slice by default
- validation runs after the final merged config is built
- file watching watches every loaded file and reloads the merged config when any file changes

Default container layout:

```text
/etc/scia/services/google.yaml
/etc/scia/services/github.yaml
/etc/scia/services/notion.yaml
/etc/scia/services/todoist.yaml
/etc/scia/services/slack.yaml
```

The runtime image should copy these files into `/etc/scia/services/`. A deployment can opt in by passing those default files before its own config:

```sh
scia -config /etc/scia/services/google.yaml -config /etc/scia/scia.yaml
```

Do not auto-load every bundled default file implicitly in the first version. Explicit `-config` order keeps startup behavior predictable and avoids accidentally enabling services that an operator did not intend to expose. A later convenience flag such as `-config-dir /etc/scia/services` can be added after the merge semantics are proven.

## OAuth Scope Parameter

Scope values and user-facing scope choices remain the responsibility of integrations. Generic service definitions should not decide which scopes exist, which scopes are enabled by default, or how they are displayed.

The service definition only decides how already-selected scope values are serialized into the authorization request sent to the provider's authorization server.

Most OAuth providers expect:

```text
?scope=value1%20value2
```

So `scopeParam` defaults to:

```yaml
scopeParam:
  name: scope
  separator: " "
```

If a provider uses another parameter name or separator, the default service YAML can override only that transport detail:

```yaml
scopeParam:
  name: user_scope
  separator: ","
```

OAuth start flow:

1. Integration metadata resolves the selected scope values.
2. Generic OAuth service joins those values with `scopeParam.separator`.
3. Generic OAuth service sends the joined value under `scopeParam.name`.
4. If no scopes are selected or `scopeParam.name` is empty, no scope parameter is sent.

## Runtime Design

Introduce an internal service registry built from config:

- `internal/integration` or `internal/service`
- `Registry.Match(host, path) []MatchedService`
- `Registry.Service(id) (Service, bool)`
- `Service.BuildInjections(ctx, request, secretStore) ([]Injection, error)`

The registry should normalize hosts the same way policy does: lowercase and strip ports for matching. `hostSuffix` must require the requested host to be longer than the suffix to avoid matching the bare suffix accidentally.

Add an `Injection` type independent of credential types:

```go
type Injection struct {
    Kind  string // header, query
    Name  string
    Value string
}
```

Then split `auth.Injector` into two layers:

- token resolvers: static bearer/basic, OAuth refresh token, client credentials
- injection appliers: header/query/basic-x-access-token

This removes provider-specific branches from request injection. Existing credential types can be implemented as compatibility adapters that produce a token plus injection strategy.

## OAuth Design

Add generic OAuth routes:

- `GET /oauth/{service}/start`
- `GET /oauth/{service}/callback`
- optional `POST /oauth/{service}/token` for token broker use cases

The existing fixed routes should keep working as aliases:

- `/oauth/google/start` resolves to configured Google-compatible service
- `/oauth/github/start` resolves to service ID `github`

OAuth flow:

1. Resolve service by path segment and validate `service.OAuth`.
2. Resolve client ID from literal or secret ref.
3. Build authorization URL from service config.
4. Store signed state with provider/service ID, user, credential ID, redirect URI, nonce, created time.
5. Exchange code at configured token URL using configured body format and client auth method.
6. Store `refresh_token` if present, otherwise `access_token`, using the same secret store semantics as today.
7. Return the existing callback template.

The generic token exchange should support:

- form body with client credentials in body
- JSON body with client credentials in body
- form body with client credentials in HTTP Basic auth
- JSON body with client credentials in HTTP Basic auth

This matches OneCLI's refresh model and covers Google, Todoist, GitHub, Notion, Dropbox, Supabase, and Atlassian-style variants. Slack's user OAuth endpoints may need a small provider-specific compatibility preset because its response shape and refresh endpoint differ from standard OAuth responses.

## Frontend Integrations API

Keep `GET /api/integrations`, but build the response from `server.services`.

The current `server.oauth.integrations` metadata can be retained temporarily as overrides:

1. service metadata from `server.services.{id}`
2. override with `server.oauth.integrations.{id}` when present
3. fallback to service ID and OAuth URLs

This keeps existing frontend behavior stable while moving the source of truth.

## MITM Host Selection

Replace fixed `integrationMITMHosts` aggregation with service host rules:

- collect exact hosts and suffix hosts from `server.services`
- include legacy `server.integrations.*.hosts` during migration
- keep default behavior unchanged when no host list is configured

This is required because HTTPS header/query injection only works through MITM.

## Migration Plan

1. Add generic config structs and validation without changing runtime behavior.
2. Add registry matching and tests for exact host, suffix host, path prefix, and port stripping.
3. Add generic injection planning for header/query/bearer/basic-x-access-token.
4. Extend `RuleConfig` with `Services []string` while keeping `Credentials []string`.
5. Add generic OAuth start/callback/token exchange routes.
6. Convert GitHub and Todoist to generic services first. They are good tests because GitHub needs `basic-x-access-token` for `github.com`, and Todoist is a standard form OAuth refresh flow.
7. Convert Google/Notion/Slack after compatibility is proven. Google needs multiple service IDs sharing one OAuth client; Notion needs default `Notion-Version`; Slack may keep a compatibility resolver if its refresh behavior remains non-standard.
8. Deprecate fixed `server.oauth.{provider}` and `server.integrations.{provider}` after one release cycle.

## Compatibility Requirements

- Existing YAML configs must continue to validate.
- Existing credential IDs such as `google`, `notion`, `todoist`, `slack`, and `github` must keep resolving.
- Existing OAuth helper URLs must continue to work.
- Existing secret storage keys must not change.
- Generic services should be additive first; removal of fixed config should be a separate breaking-change decision.

## Test Plan

Unit tests:

- config validation for valid/invalid service definitions
- registry matching for exact host, suffix host, path prefix, and port-stripped hosts
- injection rendering for bearer, basic-x-access-token, header, and query param auth
- OAuth token request encoding for form/json and body/basic client auth
- `/api/integrations` response generated from `server.services`

Integration tests:

- configure a generic Todoist service and assert a proxied request receives `Authorization: Bearer ...`
- configure a generic GitHub service and assert `api.github.com` gets Bearer while `github.com` gets Basic `x-access-token`
- configure query-param auth and assert existing query values are preserved or overwritten according to explicit policy

## Open Questions

- Should generic services be referenced by `rules.services`, or should services synthesize hidden credentials and keep `rules.credentials` as the only rule field?
- Should injection templates support only secrets and token fields, or a small Go template context with request metadata?
- Should host rewrite and request finalizers be part of the first version? OneCLI needs them for Datadog regional endpoints and AWS SigV4, but `scia` can defer them until a concrete service requires them.
- Should `server.oauth.integrations` be folded into `server.services` immediately, or kept as a metadata-only override for compatibility?
