# RBAC — Role-Based Access Control

BAMF uses a practical RBAC model with allow/deny blocks that reference resources
by labels or by name. Permissions live on roles, not on individual users.

## Concepts

**Roles** define what resources a user can access using allow and deny rules.
Rules can match resources by label or by name.

**Role assignments** map users to roles, keyed by `(provider, email)`.

**Labels** are key-value pairs on resources, reported by agents.

## Built-in Roles

Three roles are built-in and cannot be modified or deleted:

| Role | Description |
|------|-------------|
| `admin` | Full access to all resources and platform management. Deny rules do not apply. |
| `audit` | Read-only access to all platform data (users, roles, agents, audit logs, sessions). Cannot create, update, or delete anything. |
| `everyone` | Implicitly applied to all authenticated users. Grants access to resources labeled `access: everyone`. |

## Custom Roles

Create custom roles via the web UI (Roles page) or the API:

```yaml
# Example role definitions
roles:
  developer:
    allow:
      labels:
        env: [dev, staging]
      names:
        - prod-debug-jumpbox    # explicit exception
      kubernetes_groups:
        - developers
        - view
    deny:
      names:
        - staging-secrets-db

  sre:
    allow:
      labels:
        env: [dev, staging, prod]
      kubernetes_groups:
        - system:masters
    deny:
      labels:
        team: [hr]
      names:
        - prod-payroll-db
```

### Allow Rules

Allow rules grant access to resources matching the specified criteria:

- **`labels`**: Map of label keys to arrays of allowed values. A resource
  matches if it has ALL specified label keys, and for each key, the resource's
  value is in the allowed list.
- **`names`**: List of specific resource names to allow regardless of labels.
- **`kubernetes_groups`**: K8s groups the user is impersonated as when accessing
  Kubernetes resources (see [Kubernetes Guide](../guides/kubernetes.md)).

### Deny Rules

Deny rules block access to resources that would otherwise be allowed:

- **`labels`**: Deny resources matching these labels.
- **`names`**: Deny specific resources by name.

**Deny always wins.** If a resource matches both an allow and a deny rule, access
is denied.

## Evaluation Logic

```
if user has admin role:
    return ALLOW  (admin bypasses all checks)

effective_allow = {access: [everyone]}   (always present)
effective_allow += union(all role allows)
effective_deny  = union(all role denies)

can_access = matches(effective_allow) AND NOT matches(effective_deny)
```

When a user has multiple roles, allow rules are unioned (broadening access) and
deny rules are also unioned (any deny from any role blocks access).

## Role Assignments

Assign roles to users via the web UI (Access page) or the API:

![Access](../images/ui-access.png)

Assignments are keyed by `(provider_name, email)`:

```zsh
# Assign via API
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "auth0", "email": "alice@example.com", "roles": ["sre", "developer"]}'
```

Different providers can have different assignments for the same email. Role
assignments can be pre-provisioned for users who haven't logged in yet.

## SSO Claim Mapping

External identity providers can map their groups/claims to BAMF roles:

### bamf: Prefix Convention (Zero-Config)

Configure your IdP to include `bamf:`-prefixed values in group claims. BAMF
auto-recognizes them without explicit mapping:

```
IDP group "bamf:admin"  →  BAMF role "admin"
IDP group "bamf:sre"    →  BAMF role "sre"
```

### Explicit Mapping

Use `claims_to_roles` in the SSO configuration:

```yaml
auth:
  sso:
    oidc:
      auth0:
        claims_to_roles:
          - claim: https://bamf.myorg.com/groups
            value: platform-eng
            roles: [sre, developer]
          - claim: https://bamf.myorg.com/groups
            value: developers
            roles: [developer]
```

### Dual-Source Role Model

At login, roles are merged from two independent sources:

1. **IDP-derived roles** — from `bamf:` prefix convention and `claims_to_roles`
   mapping rules.
2. **Internally-assigned roles** — from the `role_assignments` table, created
   by BAMF admins.

Both sources are read-only at login. Neither writes to the other. The user
gets the union of all roles from both sources.

## Platform Roles vs Custom Roles

**Platform roles** (`admin`, `audit`) are assigned via a separate table
(`platform_role_assignments`) and grant platform management permissions.

**Custom roles** are created by admins and define resource access policies.
They are assigned via the `role_assignments` table.

Both types can be assigned via the Access page in the web UI.

## API Endpoint Authorization

| Endpoint Type | Required Role |
|---------------|---------------|
| Read (list, get) | Any authenticated user |
| Admin read (audit logs, recent users) | `admin` or `audit` |
| Write (create, update, delete) | `admin` |

## Reserved Labels

The label `access: everyone` is reserved. Resources with this label are
accessible to all authenticated users via the implicit `everyone` role.

All other label names are user-defined.

## Naming Rules

- Lowercase alphanumeric and hyphens: `[a-z0-9-]+`
- Must start with a letter: `[a-z]`
- Maximum 63 characters (DNS label compatible)
