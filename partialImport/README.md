# Keycloak Partial Authentication Import

A Keycloak 26.6.4 provider that extends realm partial import with support for authentication flows, authenticator configurations, and required actions. It returns a single, flat result set that includes both native Keycloak partial-import resources and authentication-specific resources.

## What it imports

Alongside the resources supported by Keycloak's normal partial import (for example clients, users, groups, roles, and identity providers), this provider imports:

- Authentication flows and their executions
- Authenticator configurations
- Required actions
- Realm browser-flow bindings 
- Client authentication-flow binding overrides, with imported flow IDs remapped automatically

The endpoint is transactional: if an import fails, Keycloak rolls back the transaction.

## Compatibility

| Component | Version       |
| --- |---------------|
| Java | 21            |
| Keycloak | 26.6.4        |
| Build tool | Maven Wrapper |

Use the same Keycloak version for compiling and running the provider. Keycloak's server SPI is not a stable public API across arbitrary releases.

## Build

```bash
./mvnw clean package
```

The provider JAR is written to:

```text
target/kc-partial-auth-import.jar
```

Run the test suite with:

```bash
./mvnw test
```

## Installation

1. Build the JAR.
2. Copy `target/kc-partial-auth-import.jar` into Keycloak's `providers/` directory.
3. Run an optimized build, then start Keycloak.

```bash
cp target/kc-partial-auth-import.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build
"$KEYCLOAK_HOME/bin/kc.sh" start
```

For a container deployment, add the JAR during the image build and run `kc.sh build` in that image. Do not mount an unverified JAR into a production instance at runtime.

## API

The provider factory ID is `partial-auth-import`. Its realm-admin endpoint is:

```text
POST /admin/realms/{realm}/partial-auth-import/partialImportWithAuthFlows
```

The caller must have permission to manage the realm. The endpoint accepts and returns JSON.

### Example request

```bash
curl --request POST \
  --url 'https://keycloak.example.com/admin/realms/acme/partial-auth-import/partialImportWithAuthFlows' \
  --header 'Authorization: Bearer <admin-access-token>' \
  --header 'Content-Type: application/json' \
  --data @realm-export.json
```

Use Keycloak's native `ifResourceExists` field to select the conflict policy:

```json
{
  "ifResourceExists": "OVERWRITE",
  "clients": [],
  "authenticationFlows": [],
  "authenticatorConfig": [],
  "requiredActions": []
}
```

Supported policy values are `SKIP`, `OVERWRITE`, and `FAIL`.

`authenticatorConfigs` is also accepted as an input alias for `authenticatorConfig`, so exports using either spelling can be read.

`browserFlow`, when present, is resolved by alias after the authentication flows are imported and becomes the realm's browser flow. It must name an existing top-level flow. An unresolved or blank value fails the transaction.

## Authentication-flow behavior

### Built-in flows are never overwritten

This is an intentional safety rule. A flow is skipped when either the imported representation or the existing destination flow is marked `builtIn: true`, before the selected conflict policy is evaluated.

Consequently, `OVERWRITE` applies only to non-built-in flows. Typical built-in flows such as `browser`, `direct grant`, `registration`, and built-in conditional subflows will be reported as `SKIPPED` even when the request selects `OVERWRITE`.

### Non-built-in flows

- No existing flow with the alias: imported as `ADDED`.
- Existing non-built-in flow with `OVERWRITE`: the destination flow is replaced and reported as `OVERWRITTEN`.
- Existing non-built-in flow with `SKIP`: retained and reported as `SKIPPED`.
- Existing non-built-in flow with `FAIL`: the request fails and the transaction rolls back.

When a non-built-in flow is overwritten, the provider captures and restores its realm references. It also remaps client authentication-flow binding overrides from source flow IDs to newly created destination flow IDs.

Realm defaults (browser, registration, direct grant, reset credentials, client authentication, Docker authentication, and first broker login) are also preserved across an overwrite. A captured default is temporarily moved to the corresponding built-in flow before deletion, then restored to the replacement flow. An explicit `browserFlow` in the import remains the final binding choice.

Every imported leaf execution is validated against the authenticator-provider type required by its parent flow. An unknown or blank authenticator, or duplicate flow aliases within one request, fails the transaction.

## Required-action behavior

- New aliases are added.
- Existing aliases are updated when `OVERWRITE` is selected.
- Existing aliases are skipped when `SKIP` is selected.
- Existing aliases fail the transaction when `FAIL` is selected.

For an overwrite, the incoming `providerId` must match the existing required action's `providerId`. This prevents changing a required action into a different provider implementation. The request fails if they differ.

## Response contract

The endpoint returns one `PartialAuthImportResults` document. Counts cover every result in the `results` list, including normal Keycloak resources.

```json
{
  "added": 2,
  "skipped": 1,
  "overwritten": 2,
  "results": [
    {
      "action": "OVERWRITTEN",
      "resourceType": "CLIENT",
      "id": "client-id",
      "resourceName": "my-client",
      "representation": {}
    },
    {
      "action": "OVERWRITTEN",
      "resourceType": "AUTHENTICATION_FLOW",
      "id": "destination-flow-id",
      "resourceName": "Custom Browser Flow",
      "representation": {}
    },
    {
      "action": "SKIPPED",
      "resourceType": "AUTHENTICATION_FLOW",
      "id": "existing-flow-id",
      "resourceName": "browser",
      "representation": {}
    },
    {
      "action": "OVERWRITTEN",
      "resourceType": "REQUIRED_ACTION",
      "id": "required-action-id",
      "resourceName": "CONFIGURE_TOTP",
      "representation": {}
    }
  ]
}
```

Custom resource types are `AUTHENTICATION_FLOW` and `REQUIRED_ACTION`. Native results retain Keycloak's resource-type names, such as `CLIENT`, `ROLE`, `USER`, or `GROUP`.

## Audit events

The provider emits Keycloak admin events for imported authentication resources:

- `CREATE` for added flows and required actions
- `UPDATE` for overwritten flows and required actions
- No event for skipped resources

Events use the `authentication/flows` and `authentication/required-actions` resource paths.

## Production operating guidance

- Treat import documents as privileged configuration artifacts. Store them in version control or a controlled artifact repository, and review them before use.
- Back up the realm and test the exact export against a staging realm before importing into production.
- Use least-privilege service accounts. The endpoint requires realm-management permission and can change security-critical realm configuration.
- Review the response counts and per-resource actions after every import; a successful HTTP response can legitimately contain skipped resources.
- Monitor Keycloak logs and admin events for the import request and retain the response as deployment evidence.
- Prefer explicit, non-built-in custom flows for configuration you expect to manage declaratively. Built-in flows are intentionally protected from replacement.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Built-in flow is `SKIPPED` with `OVERWRITE` | Built-in-flow safety rule | This is expected; use a custom non-built-in flow for managed changes. |
| `400 Bad Request` with an existing required action | Incoming and existing `providerId` values differ | Preserve the provider ID or create a separate required action. |
| `403 Forbidden` | Caller cannot manage the realm | Grant the appropriate realm-management permission. |
| Import fails resolving an execution/configuration | Referenced flow alias or authenticator-config alias is absent or invalid | Ensure all referenced flows and configurations are included and valid for the target Keycloak deployment. |
| Provider endpoint is unavailable | JAR is missing, service metadata is not loaded, or Keycloak was not rebuilt | Confirm the JAR is under `providers/`, then run `kc.sh build` and restart. |

## Development notes

The implementation is registered through Java's service loader at:

```text
src/main/resources/META-INF/services/org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory
```

The extension deliberately uses Keycloak internal/server APIs to integrate with the realm admin resource and partial-import manager. Validate it during every Keycloak upgrade.
