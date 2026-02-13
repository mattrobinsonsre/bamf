# SSO Configuration

BAMF supports OIDC (Auth0, Okta, Google, Azure AD, Keycloak) and SAML 2.0
identity providers. MFA is delegated to the IdP — BAMF never implements its
own MFA.

## Unified Auth Architecture

All authentication flows — local password, OIDC, SAML — use the same pipeline:

```
Client (CLI/Web UI)
  └── /auth/authorize  →  Provider login  →  /auth/callback  →  /auth/token
```

Clients never talk directly to identity providers. The flow is identical
regardless of whether the user authenticates with a password or SSO.

## OIDC Configuration

### Auth0

```yaml
auth:
  sso:
    default_provider: auth0
    oidc:
      auth0:
        issuer_url: https://myorg.us.auth0.com/
        client_id: ${BAMF_AUTH0_CLIENT_ID}       # from K8s Secret
        client_secret: ${BAMF_AUTH0_CLIENT_SECRET}
        scopes: [openid, profile, email]
        claims_to_roles:
          - claim: https://bamf.myorg.com/roles
            value: platform-eng
            roles: [admin, sre]
          - claim: https://bamf.myorg.com/roles
            value: developer
            roles: [developer]
```

**Auth0 setup:**
1. Create a Regular Web Application in Auth0
2. Set Allowed Callback URLs: `https://bamf.example.com/api/v1/auth/callback`
3. Set Allowed Logout URLs: `https://bamf.example.com`
4. Configure a Rule/Action to add group claims to the ID token

### Okta

```yaml
auth:
  sso:
    oidc:
      okta:
        issuer_url: https://myorg.okta.com
        client_id: ${BAMF_OKTA_CLIENT_ID}
        client_secret: ${BAMF_OKTA_CLIENT_SECRET}
        scopes: [openid, profile, email, groups]
        claims_to_roles:
          - claim: groups
            value: engineering
            roles: [admin, sre]
```

### Google Workspace

```yaml
auth:
  sso:
    oidc:
      google:
        issuer_url: https://accounts.google.com
        client_id: ${BAMF_GOOGLE_CLIENT_ID}
        client_secret: ${BAMF_GOOGLE_CLIENT_SECRET}
        scopes: [openid, profile, email]
```

### Generic OIDC

Any OIDC-compliant provider works:

```yaml
auth:
  sso:
    oidc:
      keycloak:
        issuer_url: https://keycloak.example.com/realms/myorg
        client_id: ${CLIENT_ID}
        client_secret: ${CLIENT_SECRET}
        scopes: [openid, profile, email]
```

## SAML 2.0 Configuration

### Azure AD (SAML)

```yaml
auth:
  sso:
    saml:
      azure-ad:
        metadata_url: https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml
        entity_id: https://bamf.example.com
        acs_url: https://bamf.example.com/api/v1/auth/saml/acs
        claims_to_roles:
          - claim: department
            value: DevOps
            roles: [admin]
```

## Credential Management

SSO client credentials should be stored in Kubernetes Secrets, not in
`values.yaml`:

```zsh
# Create the secret
kubectl -n bamf create secret generic bamf-auth0-credentials \
  --from-literal=client-id=YOUR_CLIENT_ID \
  --from-literal=client-secret=YOUR_CLIENT_SECRET
```

Then reference it in Helm values:

```yaml
auth:
  sso:
    oidc:
      auth0:
        existingSecret: bamf-auth0-credentials
        clientIdKey: client-id
        clientSecretKey: client-secret
```

## Claims-to-Roles Mapping

Two mechanisms for mapping IdP groups to BAMF roles:

### 1. bamf: Prefix Convention

Configure your IdP to include `bamf:`-prefixed values in group claims:

```
IDP group: bamf:admin    →  BAMF role: admin
IDP group: bamf:sre      →  BAMF role: sre
```

No `claims_to_roles` rules needed. The prefix is stripped automatically.

### 2. Explicit Rules

Map specific claim values to BAMF roles:

```yaml
claims_to_roles:
  - claim: groups           # claim name in the ID token
    value: platform-eng     # value to match
    roles: [sre, developer] # BAMF roles to assign
```

Both mechanisms work simultaneously. Claims from the IdP are merged with
internally-assigned roles at login.

## Enforcing SSO for Specific Roles

Prevent local password auth for privileged roles:

```yaml
auth:
  require_external_sso_for_roles:
    - admin
    - k8s-access
```

Users with these roles must authenticate via an external IdP (not local
password). This ensures IdP-level MFA policies are enforced for privileged
access.

## Multiple Providers

BAMF supports multiple providers simultaneously. Users choose their provider
at login:

```yaml
auth:
  local:
    enabled: true
  sso:
    default_provider: auth0
    oidc:
      auth0:
        issuer_url: https://myorg.us.auth0.com/
        # ...
      okta:
        issuer_url: https://myorg.okta.com
        # ...
    saml:
      azure-ad:
        metadata_url: https://login.microsoftonline.com/...
        # ...
```

The login page shows all configured providers. CLI users specify `--provider`:

```zsh
bamf login --provider auth0
bamf login --provider okta
bamf login --provider local
```

## Session Management

Sessions are stored in Redis (not JWTs). Admins can:
- View all active sessions: **Sessions** page in web UI
- Revoke a user's sessions: `DELETE /api/v1/auth/sessions/user/{email}`
- Revoke all sessions: Flush the Redis session keys

Session lifetime is configurable (default: 12 hours).
