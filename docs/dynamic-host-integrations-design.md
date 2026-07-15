# Dynamic-host integrations API design

## Summary

`GET /api/integrations` currently describes OAuth integrations whose target
hosts are known by the operator. That model cannot describe credentials such as
a GitHub Enterprise personal access token (PAT): the product is known, but each
user chooses a different enterprise host when connecting it.

Extend the integrations API with a `manual` setup definition. The OAuth helper
publishes only the form schema and a proxy-relative submission path. The
browser submits the destination and PAT directly to the proxy that will use
them. Only that proxy stores, validates, lists, rotates, or deletes the installed
binding.

The ownership invariant is:

> Integration definitions may be distributed, but installed destinations,
> secrets, verification state, and runtime metadata exist only on the proxy.

The security invariant is:

> A secret is injected only into destinations derived by the proxy from the
> validated setup values stored with that same local binding.

## Goals

- Publish setup metadata for services whose destination is selected at setup.
- Support GitHub Enterprise PATs first without making the catalog API
  GitHub-specific.
- Keep all installed-connection information local to the proxy.
- Keep secret values out of catalog, status, error, and log responses.
- Bind each credential to an exact, normalized destination.
- Permit multiple local bindings of one integration.

## Non-goals

- Store or proxy connection records in the OAuth helper or catalog service.
- Let the helper query whether a proxy has installed an integration.
- Accept arbitrary host rules or injection templates from a frontend.
- Discover destinations by following redirects or inspecting a PAT.
- Replace the existing OAuth flow in the first version.
- Allow wildcard or suffix destinations from user input.

## Trust and ownership boundaries

There are three participants:

1. **Integration catalog / OAuth helper** publishes operator-controlled
   definitions such as names, icons, field schemas, and adapter IDs. It has no
   per-user installation state.
2. **Frontend** renders a definition and sends entered values directly to the
   selected proxy. It does not send them through the helper.
3. **Proxy** owns the installed binding. It validates the destination, verifies
   the PAT, stores the secret and runtime service metadata, and injects the
   credential into matching requests.

The helper cannot list local bindings, receive PATs, receive enterprise
hostnames during setup, or call a proxy callback after registration. This is
true even when the helper and proxy happen to run in the same process: their API
and storage responsibilities remain separate.

`integration_id` is catalog data and may be shared. `binding_id` is generated
by a proxy and meaningful only on that proxy. Runtime credential IDs are derived
from local binding IDs so two installations cannot overwrite each other.

## Catalog configuration

Extend integration metadata with an operator-controlled setup schema. The
definition deliberately contains no installed destination.

```yaml
server:
  integrationDefinitions:
    github-enterprise-pat:
      name: GitHub Enterprise (PAT)
      description: Connect a GitHub Enterprise Server installation.
      released: true
      setup:
        kind: manual
        submitTo: proxy
        proxyPath: /_scia/integrations/github-enterprise-pat/bindings
        fields:
          - id: base_url
            type: url
            label: Enterprise URL
            placeholder: https://github.example.com
            required: true
          - id: token
            type: secret
            label: Personal access token
            required: true
      adapter: github-enterprise-pat
```

`adapter` selects reviewed behavior implemented by the proxy. It is safe to
publish the adapter identifier, but not internal header templates or secret
keys. Initially adapters are compiled in. A future generic adapter may be
loaded from operator-owned proxy configuration, never from a binding request.

A proxy must have the named adapter enabled locally. Receiving a catalog
definition does not install code or grant new egress access. Unknown or disabled
adapters are rejected by the proxy.

## Catalog API

Keep `GET /api/integrations`, add a version marker and `setup`. Existing OAuth
fields remain during migration.

```json
{
  "version": 2,
  "integrations": [
    {
      "id": "github-enterprise-pat",
      "name": "GitHub Enterprise (PAT)",
      "released": true,
      "setup": {
        "kind": "manual",
        "submit_to": "proxy",
        "proxy_path": "/_scia/integrations/github-enterprise-pat/bindings",
        "fields": [
          {
            "id": "base_url",
            "type": "url",
            "label": "Enterprise URL",
            "required": true
          },
          {
            "id": "token",
            "type": "secret",
            "label": "Personal access token",
            "required": true
          }
        ]
      },
      "capabilities": {
        "multiple_bindings": true,
        "verify_on_create": true
      }
    }
  ]
}
```

`proxy_path` is relative. The catalog must not choose or return a proxy origin.
The frontend already knows which proxy it is configuring and resolves the path
against that trusted origin. This prevents a catalog response from redirecting
the PAT to another server.

The catalog response contains no binding IDs, destinations, verification
results, secret references, injection templates, or binding counts.

## Proxy-local API

These endpoints are served only by the proxy and use the proxy's existing
user/admin authorization boundary. They are not mounted on the OAuth helper.

### Create a binding

```http
POST /_scia/integrations/github-enterprise-pat/bindings
Authorization: Bearer <proxy user token>
Idempotency-Key: <uuid>
Content-Type: application/json

{
  "display_name": "Corp GitHub",
  "values": {
    "base_url": "https://github.example.com/",
    "token": "github_pat_..."
  },
  "verify": true
}
```

The proxy looks up the locally enabled adapter, validates only its declared
fields, creates an opaque local `binding_id`, and materializes runtime metadata.
Successful response never echoes the PAT:

```json
{
  "id": "bind_01JABC...",
  "integration_id": "github-enterprise-pat",
  "display_name": "Corp GitHub",
  "destination": {
    "origin": "https://github.example.com",
    "host": "github.example.com"
  },
  "status": "active",
  "verified_at": "2026-07-15T12:00:00Z",
  "created_at": "2026-07-15T12:00:00Z"
}
```

Use `201 Created`; a replayed idempotency key returns the same local result.
Return stable errors such as `invalid_url`, `port_not_allowed`,
`destination_not_allowed`, and `verification_failed`. Do not relay upstream
response bodies.

### Manage local bindings

```text
GET    /_scia/integration-bindings
GET    /_scia/integration-bindings/{binding_id}
PATCH  /_scia/integration-bindings/{binding_id}
DELETE /_scia/integration-bindings/{binding_id}
POST   /_scia/integration-bindings/{binding_id}/verify
PUT    /_scia/integration-bindings/{binding_id}/secret
```

- All responses and operations remain on the proxy.
- `GET` contains local destination and status metadata, never secrets.
- `PATCH` changes only `display_name` in v1. Changing a destination creates a
  new binding so a credential is never silently rebound.
- `PUT .../secret` rotates and verifies a secret for the immutable destination,
  then atomically replaces the stored value.
- `DELETE` removes the local secret, metadata, and runtime index.

The existing `POST /_scia/tokens` remains an administrator API. The frontend
must not use it for manual setup because it accepts caller-provided
`ServiceConfig`, including injection behavior. The binding endpoint accepts
only adapter fields and constructs service metadata inside the proxy.

## GitHub Enterprise PAT adapter

For `base_url: https://github.example.com`, the proxy adapter produces local
runtime metadata equivalent to:

```yaml
hosts:
  - host: github.example.com
    pathPrefix: /api/v3/
    authMethod: bearer
injection:
  headers:
    - name: Authorization
      value: "Bearer {{ .access_token }}"
```

It verifies with `GET /api/v3/user`, expects `200`, and never follows redirects.
The adapter may later add Git LFS or upload hosts only as reviewed explicit
rules. It must not derive `*.example.com` from `github.example.com`.

## Destination validation

For a URL destination, the proxy:

1. Requires HTTPS by default.
2. Rejects user info, fragments, query strings, encoded host characters, an
   empty host, and non-root paths unless an adapter supports a base path.
3. Lowercases DNS names, removes one trailing dot, converts IDNs to ASCII, and
   rejects invalid labels.
4. Allows only locally configured ports and rejects IP literals unless locally
   enabled.
5. Resolves every DNS answer during verification and applies local egress
   policy to all of them.
6. Pins verification to a validated address while retaining the original
   Host/SNI and does not follow redirects.
7. Re-applies egress and DNS checks at request time because DNS may change.

Enterprise servers often use private networks, so a proxy operator may allow
private ranges. Loopback, link-local, cloud metadata ranges, proxy/admin
listeners, cluster control endpoints, and local deny lists remain blocked. The
catalog and frontend cannot weaken these controls.

## Proxy-local storage and runtime projection

The proxy stores all binding state in its configured secret backend namespace:

```text
binding/{owner}/{binding_id}/metadata
binding/{owner}/{binding_id}/secret/access_token
binding-index/{owner}/{integration_id}/{binding_id}
service/{owner}/{binding_id}/metadata
```

Nothing is written back to the OAuth helper, catalog service, or a shared
connection database. The service projection is produced only by the local
adapter and normalized with `serviceinfo.Normalize`.

Runtime matching includes the local owner and binding ID so one user's binding
cannot authenticate another user's request. A deployment that isolates each
proxy per user may keep this ownership implicit in the proxy instance, but must
not create globally shared credential IDs.

If the local secret backend lacks transactions, the proxy writes under a
pending binding ID, publishes its index last, and garbage-collects stale pending
records. Runtime lookup sees only indexed bindings. Rotation writes a new secret
version, verifies it, then swaps the active local reference.

## Definition delivery and versioning

The proxy must not depend on the helper at request time. There are two valid
deployment models:

- The proxy has the same operator-owned definitions in configuration.
- The proxy caches signed/versioned public definitions from the helper, while
  retaining a local allowlist of enabled adapters and egress policy.

In either model, the proxy stores `definition_version` and `adapter_version` in
local binding metadata. Removing a catalog entry prevents new setup in the UI
but does not remotely delete or disable existing local bindings. Such lifecycle
changes require a local proxy operation. Adapter changes that broaden a
destination or injection rule require an explicit local migration.

## Audit and observability

- The proxy audits binding ID, local owner, normalized destination, operation,
  result, and adapter version. The helper has no binding audit events because it
  is not involved.
- Create and verify are rate-limited locally per owner and destination.
- The proxy redacts secret fields from errors, request dumps, traces, and
  upstream response bodies.
- Metrics use integration ID and result code; raw enterprise hostnames are
  omitted by default because they may be sensitive.

## Request flow

1. Frontend fetches the public definition from `GET /api/integrations`.
2. Frontend renders `base_url` and `token` fields.
3. Frontend submits them directly to the trusted proxy origin plus the relative
   `proxy_path`.
4. Proxy validates its locally enabled adapter and destination policy.
5. Proxy verifies the PAT against a pinned destination.
6. Proxy atomically stores the local binding, secret, projection, and index.
7. Subsequent agent traffic is matched and injected entirely by the proxy; the
   helper is not consulted.

## Rollout

1. Add v2 catalog fields while preserving the existing OAuth response shape.
2. Implement proxy-local binding storage and the GitHub Enterprise PAT adapter
   behind a feature flag.
3. Add proxy-local list, deletion, verification, and rotation endpoints.
4. Enable the adapter and definition for internal users.
5. Publish the definition after frontend support is deployed.

## Test plan

- Catalog JSON contains setup fields but no binding or injection internals.
- Creating a binding generates no request or write to the OAuth helper.
- The PAT request body is sent only to the configured proxy origin.
- Two bindings for one definition receive distinct local credential IDs.
- A PAT bound to one enterprise host is never injected into another host,
  subdomain, redirect target, alternate port, or changed DNS destination.
- URL parsing rejects user info, paths, queries, fragments, Unicode confusion,
  IP literals, and disallowed ports as configured.
- DNS rebinding, multiple A/AAAA answers, private ranges, link-local and metadata
  endpoints exercise local policy at verification and request time.
- Verification does not follow redirects or leak upstream bodies.
- Rotation is atomic; failed verification leaves the old secret active.
- Deletion removes all local secret, metadata, service, and index records.
- Catalog removal does not remotely mutate an existing proxy binding.
- Logs, traces, API errors, and audit events never contain submitted secrets.
- Legacy OAuth integrations and administrator `/_scia/tokens` remain unchanged.

## Decisions

- The helper owns definitions only; the proxy exclusively owns bindings.
- The frontend submits secrets directly to a known proxy using a relative path.
- Destinations are immutable local binding data, never catalog metadata.
- User input supports exact origins only; wildcards remain operator-controlled.
- Manual setup uses locally enabled, reviewed adapters in v1.
- No central connection lifecycle API is introduced.
