# Dynamic-host integrations API design

## Summary

`GET /api/integrations` currently describes OAuth integrations whose target
hosts are known by the operator. That model cannot safely describe credentials
such as a GitHub Enterprise personal access token (PAT): the product is known,
but each user chooses a different enterprise host when connecting it.

Add a second integration mode, `manual`, whose public definition contains a
small, server-defined setup form. Submitting that form creates an immutable
credential binding between one secret and a normalized set of destination
hosts. The frontend never submits arbitrary `ServiceConfig` or injection
templates.

The central security invariant is:

> A secret is only injected into destinations derived by the server from the
> validated setup values stored with that same credential instance.

This keeps integrations discoverable through the same API while preventing a
frontend or compromised agent from turning a stored PAT into an unrestricted
forward-proxy credential.

## Goals

- Expose integrations whose destination host is selected at setup time.
- Support GitHub Enterprise PATs first, without making the API GitHub-specific.
- Keep secret values out of integration, connection, and error responses.
- Make the credential-to-host binding explicit, auditable, and revocable.
- Reuse the existing service metadata matcher and injector after setup.
- Permit multiple connections of one integration, for example two GitHub
  Enterprise installations.

## Non-goals

- Accept arbitrary host rules or injection templates from an untrusted client.
- Discover every host by following redirects or inspecting the PAT.
- Verify that a token has particular upstream permissions.
- Replace the existing OAuth flow in the first version.
- Allow wildcard or suffix destinations from user input.

## Model

Separate the current overloaded notion of an integration into two resources:

1. **Integration definition**: operator-controlled metadata and setup schema.
   Its ID is stable, for example `github-enterprise-pat`.
2. **Connection**: a user-scoped installed instance containing the normalized
   destination, generated credential ID, non-secret display metadata, and
   secret-store references. Its ID is opaque, for example `con_01J...`.

An OAuth integration is still represented by a definition, but uses
`setup.kind: oauth`. A PAT-style integration uses `setup.kind: manual`.
Connections give both kinds a common lifecycle API over time, although OAuth
connection migration is not required for v1.

The connection ID, not the definition ID, is used as the runtime credential ID.
This prevents two installations of the same product from overwriting each
other. Runtime service metadata is materialized under the connection ID.

## Configuration

Extend the metadata currently held in `server.oauth.integrations` into a
top-level definition registry. Keep the old location as a compatibility input.

```yaml
server:
  integrationDefinitions:
    github-enterprise-pat:
      name: GitHub Enterprise (PAT)
      description: Connect a GitHub Enterprise Server installation.
      released: true
      setup:
        kind: manual
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
        verification:
          method: GET
          path: /api/v3/user
          expectedStatus: [200]
      binding:
        adapter: github-enterprise-pat
        destinationField: base_url
        secretField: token
        allowPrivateNetworks: true
        allowedPorts: [443]
```

`adapter` selects audited server-side code. The public configuration does not
contain header templates, secret keys, host suffixes, or arbitrary verification
URLs. Initially adapters are compiled in. A future generic adapter may be
allowed only from operator-owned config, never from the create-connection body.

For GitHub Enterprise, the adapter produces the following runtime metadata:

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

The adapter may optionally add a second, explicitly reviewed rule for Git LFS
or other endpoints. It must not infer `*.example.com` from
`github.example.com`.

## Public API

### List definitions

Keep `GET /api/integrations`, add a version marker, `setup`, and `capabilities`.
Existing OAuth fields remain during migration.

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
        "multiple_connections": true,
        "verify_on_create": true
      }
    }
  ]
}
```

The response must not expose binding configuration, verification headers,
secret-store keys, injection templates, or upstream credentials.

### Create a connection

```http
POST /api/integrations/github-enterprise-pat/connections
Authorization: Bearer <user token>
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

Successful response:

```json
{
  "id": "con_01JABC...",
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

Use `201 Created` for a new connection and return the same result for a replayed
idempotency key. Never echo the secret. Return validation errors using stable
field codes, for example `invalid_url`, `port_not_allowed`,
`destination_not_allowed`, or `verification_failed`; upstream response bodies
must not be relayed.

`verify: false` is accepted only when the definition permits it. Otherwise the
server verifies before committing. Verification sends the secret directly to
the normalized destination using the adapter's fixed method and path.

### Manage connections

```text
GET    /api/integration-connections
GET    /api/integration-connections/{connection_id}
PATCH  /api/integration-connections/{connection_id}
DELETE /api/integration-connections/{connection_id}
POST   /api/integration-connections/{connection_id}/verify
PUT    /api/integration-connections/{connection_id}/secret
```

- `GET` responses contain destination and status metadata, never secrets.
- `PATCH` may change only `display_name` in v1. Changing a destination creates a
  new connection so a credential is never silently rebound to another host.
- `PUT .../secret` rotates the secret for the existing immutable destination,
  verifies it, and atomically replaces the stored value.
- `DELETE` removes the token, runtime metadata, and index entry atomically (or
  marks the connection deleting until all three operations finish).

All endpoints are user-scoped by default. Team-scoped connections require a
separate permission and explicit `scope`/`team_id`; they must not be inferred
from the integration definition.

## Destination normalization and validation

For a `url` destination field:

1. Parse with a strict URL parser. Require `https` by default.
2. Reject user info, fragments, query strings, encoded host characters, and an
   empty host. Reject a non-root path unless the adapter explicitly supports a
   base path.
3. Lowercase the DNS name, remove one trailing dot, convert IDNs to ASCII, and
   reject invalid DNS labels. Store the canonical origin and host separately.
4. Permit only adapter-configured ports. Store an explicit non-default port as
   part of the origin and runtime match key.
5. Reject IP literals unless the operator explicitly permits them.
6. Resolve all DNS answers during verification. Apply the deployment's
   private/link-local/loopback/metadata-address policy to every answer.
7. Pin the verification connection to a validated address while retaining the
   original Host/SNI. Do not follow redirects. This prevents DNS rebinding and
   redirect-based secret exfiltration.
8. Re-apply egress policy and DNS checks at request time. Creation-time
   validation alone is not sufficient because DNS can change.

Enterprise installations commonly use private networks, so private addresses
may be enabled per definition by an operator. Even then, loopback, link-local,
cloud metadata ranges, the proxy/admin listener, cluster control endpoints, and
operator deny lists remain blocked. The UI cannot override these controls.

## Storage and runtime projection

Store one connection record and its secret transactionally where supported:

```text
connection/{owner}/{connection_id}/metadata
connection/{owner}/{connection_id}/secret/access_token
connection-index/{owner}/{integration_id}/{connection_id}
service/{owner}/{connection_id}/metadata
```

The service projection is produced only by the selected adapter and normalized
with `serviceinfo.Normalize`. Extend runtime matching to include owner and
connection ID so one user's connection cannot authenticate another user's
request. If the current deployment uses per-user secret stores, preserve that
namespace instead of creating global credential IDs.

The existing `POST /_scia/tokens` endpoint can remain an administrator API. It
must not be exposed to the frontend as the implementation of manual setup,
because it accepts caller-provided `ServiceConfig`, including injection
behavior. The new endpoint accepts only fields declared in the definition and
uses a server-side adapter to construct service metadata.

Configuration reload behavior:

- Existing connections retain the adapter version used to materialize them.
- A definition removed or set to `released: false` cannot create new
  connections; existing connections continue unless explicitly disabled.
- An adapter change requiring broader destinations or injection behavior needs
  an explicit migration. It must not silently broaden existing bindings.

## Authorization, audit, and observability

- Creating, rotating, verifying, listing, and deleting connections requires an
  authenticated user and owner check.
- Rate-limit create and verify operations per user and destination.
- Audit definition ID, connection ID, owner, normalized destination, operation,
  result, and adapter version. Never log submitted values wholesale.
- Redact configured secret fields from structured errors, request dumps,
  tracing attributes, and upstream error bodies.
- Emit metrics by integration ID and result code, not raw destination by
  default; enterprise hostnames may be sensitive.
- Return generic verification failures to clients and keep sanitized diagnostic
  detail in privileged logs.

## Failure atomicity

Connection creation follows this order:

1. Validate definition, declared fields, destination, authorization, and quota.
2. Build the adapter-owned runtime projection in memory.
3. Verify against the pinned destination when required.
4. Commit connection metadata, secret, projection, and indexes.
5. Return only non-secret metadata.

If the secret backend cannot provide a transaction, write under a pending
connection ID, publish the index last, and garbage-collect stale pending data.
Runtime lookups only see indexed connections. Secret rotation similarly writes
a new version, verifies it, then swaps the active reference.

## Compatibility and rollout

1. Add the v2 response fields while keeping the existing OAuth response shape.
   Clients that ignore unknown fields continue to work.
2. Implement connection storage and the GitHub Enterprise PAT adapter behind a
   feature flag.
3. Add user-scoped runtime projection and deletion/rotation APIs.
4. Enable the manual definition for internal users and audit failed destination
   validations.
5. Publish the definition after frontend support is deployed.
6. Later, represent OAuth authorizations as connections and deprecate the
   provider-specific top-level fields.

## Test plan

- Definition JSON contains setup fields but no binding or injection internals.
- Two connections for one definition receive distinct credential IDs and hosts.
- A PAT bound to `github.corp.example` is never injected into another host,
  subdomain, redirect target, alternate port, or changed DNS destination.
- URL parsing rejects user info, paths, queries, fragments, Unicode confusion,
  IP literals, and disallowed ports as configured.
- DNS rebinding, multiple A/AAAA answers, private ranges, link-local and metadata
  endpoints exercise the same egress policy at verification and request time.
- Verification does not follow 3xx responses and does not leak upstream bodies.
- Create idempotency cannot duplicate connections or overwrite another user's
  secret.
- Rotation is atomic; failed verification leaves the old secret active.
- Deletion removes the secret, metadata, service index, and runtime match.
- Logs, traces, API errors, and audit events never contain submitted secrets.
- Legacy OAuth integrations and administrator `/_scia/tokens` behavior remain
  unchanged.

## Decisions

- Dynamic destinations are connection data, not mutable integration metadata.
- Destination changes create a new connection; they do not mutate a binding.
- User input supports exact origins only. Wildcards and suffix rules remain
  operator-controlled.
- Manual setup uses compiled, audited adapters in v1.
- The integration catalog and connection lifecycle are public frontend APIs;
  raw service metadata remains an internal/admin API.
