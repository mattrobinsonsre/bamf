# SSO Configuration

BAMF supports OIDC (Auth0, Okta, JumpCloud, Google, Azure AD, Keycloak) and SAML 2.0
identity providers. MFA is delegated to the IdP — BAMF never implements its
own MFA.

## Authentication vs Authorization

Each provider section below is split into two parts:

- **Authentication only** — the minimum setup to let users log in via SSO.
  Roles are assigned internally by a BAMF admin via the API or web UI. This is
  the simplest path and works with every OIDC provider identically.

- **Authentication + Authorization** — additional IdP configuration so the
  provider sends role/group information in the token. This lets the IdP control
  who gets which BAMF roles, avoiding manual role assignment in BAMF. This is
  where provider-specific complexity lives.

**You don't need authz from the IdP.** If you just want SSO login and are
happy assigning roles in BAMF, stop after the authentication setup. The
authorization setup is only needed if you want the IdP to be the source of
truth for role membership.

## How Role Assignment Works

BAMF resolves roles from three sources at login (all merged together):

1. **IdP-derived roles** — groups or permissions from the identity provider
   token. Only available if you complete the authorization setup for your
   provider.
2. **`claims_to_roles` mapping** — explicit config rules that translate
   arbitrary IdP claim values to BAMF role names.
3. **Internal role assignments** — roles assigned by a BAMF admin via the API,
   keyed by `(provider_name, email)`. Always available regardless of IdP
   capabilities.

If you only do authentication setup, source 1 is empty and roles come
entirely from sources 2 and 3.

### Role Prefix Stripping

By default, BAMF automatically strips `bamf:` and `bamf-` prefixes from
group names before using them as role names. For example, an Okta group
`bamf-admin` becomes BAMF role `admin`.

This is configurable per provider via `rolePrefixes`. Set it to `[]` (empty
list) to disable prefix stripping entirely, or to custom prefixes for your
organization:

```yaml
auth:
  sso:
    oidc:
      okta:
        rolePrefixes: ["myorg-", "myorg:"]  # custom prefixes
      auth0:
        rolePrefixes: []  # disable (Auth0 permissions are already plain names)
```

The default `["bamf:", "bamf-"]` works well for Okta and other providers
where groups are tenant-wide and you want to namespace them.

## Unified Auth Architecture

All authentication flows — local password, OIDC, SAML — use the same pipeline:

```
Client (CLI/Web UI)
  +-- /auth/authorize  ->  Provider login  ->  /auth/callback  ->  /auth/token
```

Clients never talk directly to identity providers. The flow is identical
regardless of whether the user authenticates with a password or SSO.

---

## Auth0

### Authentication Setup (5 minutes)

This gets users logging in via Auth0. No permissions, no API registration,
no RBAC configuration. Roles are assigned internally in BAMF.

**1. Create a Regular Web Application**

1. Go to **Applications -> Create Application -> Regular Web Applications**
2. On the Settings tab, configure:
   - **Allowed Callback URLs**: `https://bamf.example.com/api/v1/auth/callback`
   - **Allowed Logout URLs**: `https://bamf.example.com`
3. Note the **Client ID** and **Client Secret**

**2. Configure BAMF**

```yaml
auth:
  sso:
    defaultProvider: auth0
    oidc:
      auth0:
        enabled: true
        displayName: "Auth0"
        issuerUrl: https://YOUR_TENANT.us.auth0.com/
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-auth0
        existingSecretKey: client_secret
```

```zsh
kubectl -n bamf create secret generic bamf-auth0 \
  --from-literal=client_secret=YOUR_CLIENT_SECRET
```

**3. Assign roles in BAMF**

After users log in, assign roles via the BAMF admin API or web UI:

```zsh
# Grant admin role to an Auth0 user
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "auth0", "email": "alice@example.com", "roles": ["admin"]}'
```

That's it. Users can log in via Auth0 and you control their roles in BAMF.

### Authorization Setup (Auth0 manages roles)

If you want Auth0 to control which users get which BAMF roles — so you don't
have to assign them manually in BAMF — you need to register an Auth0 API
(resource server) and configure RBAC permissions on it.

**This adds significant Auth0 configuration** but means role changes happen
in Auth0 and take effect on the next login, with no BAMF admin action needed.

**1. Register BAMF as an API**

1. Go to **Applications -> APIs -> Create API**
2. Configure:
   - **Name**: `BAMF`
   - **Identifier**: `https://bamf.example.com/api` (this becomes the `audience`)
   - **Signing Algorithm**: RS256

**2. Define permissions on the API**

1. Click the BAMF API -> **Permissions** tab
2. Add permissions matching your BAMF role names:

| Permission | Description |
|---|---|
| `admin` | Full platform administration |
| `ssh-access` | SSH access to servers |
| `k8s-access` | Kubernetes cluster access |
| `audit` | Read-only audit log access |

**3. Enable RBAC on the API**

1. Click the BAMF API -> **Settings** tab -> scroll to **RBAC Settings**
2. Toggle ON: **Enable RBAC**
3. Toggle ON: **Add Permissions in the Access Token**

This makes Auth0 include the user's permissions in the access token JWT.

**4. Authorize the application for the API**

1. Click the BAMF API -> **Machine to Machine Applications** tab
   (or **Application Access** if shown)
2. Find your BAMF application -> toggle it ON or click Authorize
3. Save

**5. Assign permissions to users**

*Option A -- Direct assignment:*
1. Go to **User Management -> Users -> select user -> Permissions tab**
2. Click **Add Permissions -> select the BAMF API -> check the permissions**

*Option B -- Via Auth0 Roles (recommended for many users):*
1. Go to **User Management -> Roles -> Create Role** (e.g., "BAMF Admin")
2. Click the role -> **Permissions tab -> Add Permissions -> select BAMF API
   -> check `admin`**
3. Go to the **Users tab** on the role and assign users

Auth0 Roles are a grouping convenience — they bundle permissions for easier
assignment. The role name in Auth0 (e.g., "BAMF Admin") is separate from the
permission name (`admin`) that BAMF sees.

**6. Update BAMF config to include the audience**

Add the `audience` field to your existing config:

```yaml
auth:
  sso:
    oidc:
      auth0:
        enabled: true
        displayName: "Auth0"
        issuerUrl: https://YOUR_TENANT.us.auth0.com/
        clientId: YOUR_CLIENT_ID
        audience: https://bamf.example.com/api  # must match API Identifier
        rolePrefixes: []  # Auth0 permissions are already plain names
        existingSecret: bamf-auth0
        existingSecretKey: client_secret
```

### What Auth0 sends to BAMF (with authz)

When a user with `admin` and `ssh-access` permissions logs in, Auth0 returns
an access token JWT containing:

```json
{
  "iss": "https://YOUR_TENANT.us.auth0.com/",
  "aud": "https://bamf.example.com/api",
  "permissions": ["admin", "ssh-access"]
}
```

BAMF decodes the access token, extracts the `permissions` array, and maps
each permission directly to a BAMF role name.

### Auth0 Troubleshooting

**Login works but no roles appear**

If you completed the authorization setup, check:
1. The `audience` field in BAMF config matches the API Identifier in Auth0
   exactly (including trailing slash if present)
2. RBAC is enabled on the API with "Add Permissions in the Access Token" ON
3. The user has permissions assigned (directly or via an Auth0 Role)
4. The application is authorized for the API

If you only did authentication setup, roles must be assigned in BAMF — Auth0
won't send any.

---

## Okta

### Authentication Setup (5 minutes)

This gets users logging in via Okta. No groups, no custom authorization
server, no claims configuration. Roles are assigned internally in BAMF.

**1. Create an OIDC Web Application**

1. In the Okta admin console, go to **Applications -> Create App Integration**
2. Sign-in method: **OIDC - OpenID Connect**
3. Application type: **Web Application**
4. Configure:
   - **App integration name**: `BAMF`
   - **Sign-in redirect URIs**: `https://bamf.example.com/api/v1/auth/callback`
   - **Sign-out redirect URIs**: `https://bamf.example.com`
   - **Controlled access**: "Allow everyone in your organization to access"
     (or limit to specific groups)
5. Click **Save**
6. Note the **Client ID** and **Client Secret** from the General tab

> **Which issuer URL?** For authentication only, you can use either the Org
> Authorization Server (`https://YOUR_ORG.okta.com`) or a Custom Authorization
> Server (`https://YOUR_ORG.okta.com/oauth2/default`). Both work for basic
> login. However, if you think you might add authorization later, start with
> the Custom AS URL to avoid having to change it.

**2. Configure BAMF**

```yaml
auth:
  sso:
    defaultProvider: okta
    oidc:
      okta:
        enabled: true
        displayName: "Okta"
        issuerUrl: https://YOUR_ORG.okta.com/oauth2/default
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-okta
        existingSecretKey: client_secret
```

```zsh
kubectl -n bamf create secret generic bamf-okta \
  --from-literal=client_secret=YOUR_CLIENT_SECRET
```

**3. Assign roles in BAMF**

After users log in, assign roles via the BAMF admin API or web UI:

```zsh
# Grant admin role to an Okta user
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "okta", "email": "alice@example.com", "roles": ["admin"]}'
```

That's it. Users can log in via Okta and you control their roles in BAMF.

### Authorization Setup (Okta manages roles)

If you want Okta group membership to control BAMF roles — so that adding a
user to the `bamf-admin` Okta group automatically grants them the BAMF `admin`
role — you need to configure a Custom Authorization Server with custom scopes,
claims, and access policies.

> **Fair warning**: this is significantly more involved than the authentication
> setup. Okta's Custom Authorization Server requires configuring four separate
> things (scope, claim, access policy, groups) across multiple admin console
> pages. Each one is individually simple but all four must be correct or the
> login will fail with unhelpful error messages. Follow each step carefully.

#### Prerequisites

You **must** use a **Custom Authorization Server** for authorization. The Org
Authorization Server (`https://YOUR_ORG.okta.com` without `/oauth2/...`) does
not support custom claims, custom scopes, or access policies. It cannot send
group membership to BAMF.

The issuer URL in your BAMF config must include `/oauth2/<server-id>`:
- `https://YOUR_ORG.okta.com/oauth2/default` (the built-in Custom AS)
- `https://YOUR_ORG.okta.com/oauth2/aus...` (a custom one you created)

If your authentication setup uses the Org AS URL, change it now.

#### Step 1: Create groups with `bamf-` prefix

1. Go to **Directory -> Groups -> Add Group**
2. Create groups matching your BAMF roles, prefixed with `bamf-`:

| Okta Group | BAMF Role (after prefix strip) |
|---|---|
| `bamf-admin` | `admin` |
| `bamf-ssh-access` | `ssh-access` |
| `bamf-k8s-access` | `k8s-access` |
| `bamf-audit` | `audit` |

3. Click each group -> **Assign people** -> add the appropriate users

The `bamf-` prefix namespaces these groups to BAMF so they don't conflict with
groups used by other applications in your Okta tenant.

#### Step 2: Add the `groups` scope to the Custom Authorization Server

Without this scope, Okta returns a 400 error when BAMF requests group
information during login.

1. Go to **Security -> API -> Authorization Servers**
2. Click **`default`** (or your Custom AS)
3. Click the **Scopes** tab
4. Click **Add Scope**:
   - **Name**: `groups`
   - **Display phrase**: `Access to group membership`
   - **Description**: `Allows the application to read group membership`
   - Leave other options at defaults
5. Click **Create**

#### Step 3: Add the `groups` claim to the Custom Authorization Server

This tells Okta to include group membership in the ID token.

1. Still on the Custom AS page, click the **Claims** tab
2. Click **Add Claim**:
   - **Name**: `groups`
   - **Include in token type**: **ID Token** -> **Always**
   - **Value type**: **Groups**
   - **Filter**: **Matches regex** -> `.*`
     (or **Starts with** -> `bamf-` to only send BAMF groups)
   - **Include in**: **Any scope**
3. Click **Create**

> **Filter options**: "Matches regex `.*`" sends all groups. "Starts with
> `bamf-`" sends only BAMF-prefixed groups (smaller token, less data leakage).
> Either works — BAMF only acts on groups matching its role definitions.
>
> **Important**: The "Starts with" filter value cannot be left blank. If you
> want all groups, use "Matches regex" with `.*`.

#### Step 4: Create an Access Policy on the Custom Authorization Server

**This is the step most likely to be missed**, and the error message ("You are
not allowed to access this app") gives no indication that access policies are
the problem. Custom Authorization Servers ship with **no access policies** by
default. Without a policy, every token request is rejected.

1. Still on the Custom AS page, click the **Access Policies** tab
2. Click **Add Policy**:
   - **Name**: `Default Policy`
   - **Description**: `Allow all clients`
   - **Assign to**: **All clients**
3. Click **Create Policy**
4. You'll be prompted to add a rule. Click **Add Rule**:
   - **Rule Name**: `Default Rule`
   - **Grant type is**: check **Authorization Code**
   - **User is**: **Any user assigned the app**
   - **Scopes requested**: **Any scopes**
   - Leave token lifetime defaults
5. Click **Create Rule**

> **Why?** The Org Authorization Server uses app assignments to control access.
> Custom Authorization Servers ignore app assignments for token issuance and
> use access policies instead. An empty Access Policies tab = nobody can get a
> token, regardless of app assignments.

#### Step 5: Assign users to the application

If you already configured this during authentication setup, no changes needed.
Otherwise:

1. Go to **Applications -> your BAMF app -> Assignments tab**
2. Assign users or groups (assigning the `bamf-admin` group gives access to
   all its members)

#### Step 6: Verify with Token Preview

Before updating BAMF, verify Okta is sending the right claims:

1. Go to **Security -> API -> Authorization Servers -> `default`**
2. Click the **Token Preview** tab
3. Configure:
   - **OAuth/OIDC client**: your BAMF application
   - **Grant type**: Authorization Code
   - **User**: a test user in the `bamf-admin` group
   - **Scopes**: `openid profile email groups`
4. Click **Preview Token** -> select the **Token** tab
5. Verify the payload contains:
   ```json
   {
     "groups": ["bamf-admin"],
     ...
   }
   ```

If `groups` is missing, recheck Steps 2-4.

#### Step 7: Update BAMF config for authorization

Add `scopes` and `groupsClaim` to your existing config:

```yaml
auth:
  sso:
    oidc:
      okta:
        enabled: true
        displayName: "Okta"
        # Must be a Custom Authorization Server URL
        issuerUrl: https://YOUR_ORG.okta.com/oauth2/default
        clientId: YOUR_CLIENT_ID
        scopes: ["openid", "profile", "email", "groups"]
        groupsClaim: groups
        existingSecret: bamf-okta
        existingSecretKey: client_secret
```

### What Okta sends to BAMF (with authz)

When a user in the `bamf-admin` and `bamf-ssh-access` groups logs in, the ID
token contains:

```json
{
  "iss": "https://YOUR_ORG.okta.com/oauth2/default",
  "groups": ["bamf-admin", "bamf-ssh-access"]
}
```

BAMF strips the `bamf-` prefix, yielding roles `admin` and `ssh-access`.

### Alternative: explicit claims_to_roles mapping

If you have existing Okta groups with different names and can't (or don't want
to) create `bamf-` prefixed groups, use `claims_to_roles` to map them:

```yaml
auth:
  sso:
    oidc:
      okta:
        enabled: true
        issuerUrl: https://YOUR_ORG.okta.com/oauth2/default
        clientId: YOUR_CLIENT_ID
        scopes: ["openid", "profile", "email", "groups"]
        groupsClaim: groups
        rolePrefixes: []  # disable prefix stripping
        claimsToRoles:
          - claim: groups
            value: Platform-Engineering
            roles: [admin, ssh-access]
          - claim: groups
            value: Developers
            roles: [ssh-access]
```

Configure the groups claim filter to include the relevant groups ("Matches
regex `.*`" to include all).

### Okta Troubleshooting

**"One or more scopes are not configured for the authorization server resource"**

The `groups` scope hasn't been created on the Custom Authorization Server.
See Step 2 (Security -> API -> Authorization Servers -> default -> Scopes ->
Add Scope named `groups`).

**"You are not allowed to access this app"**

The Custom Authorization Server has no access policies. This is **not** an
app assignment issue. See Step 4 (Security -> API -> Authorization Servers ->
default -> Access Policies -> Add Policy + Add Rule).

**Groups array is empty in BAMF logs**

Check in order:

1. **Issuer URL**: Must point to a Custom Authorization Server
   (`https://YOUR_ORG.okta.com/oauth2/default`), not the Org AS
   (`https://YOUR_ORG.okta.com`). The Org AS can't send custom claims.
2. **Scopes in BAMF config**: Must include `"groups"`.
3. **`groups` scope on Custom AS**: Must exist (Scopes tab).
4. **`groups` claim on Custom AS**: Must exist with Value type "Groups"
   (Claims tab).
5. **User is in groups**: Check Directory -> Groups -> members.
6. **Token Preview**: Use it to verify claims before debugging BAMF.

**"The token is not valid as it was issued in the future"**

Clock skew between the API pod and Okta. Usually transient — retry. If
persistent, check NTP on the Kubernetes nodes.

---

## Azure AD (Entra ID)

### Authentication Setup

**1. Register an application**

1. Azure Portal -> **Entra ID -> App registrations -> New registration**
2. Redirect URI: Web -> `https://bamf.example.com/api/v1/auth/callback`
3. Note the **Application (client) ID** and **Directory (tenant) ID**

**2. Create a client secret**

1. Go to **Certificates & secrets -> New client secret**
2. Note the secret value

**3. Configure BAMF**

```yaml
auth:
  sso:
    oidc:
      azure:
        enabled: true
        displayName: "Microsoft Entra ID"
        issuerUrl: https://login.microsoftonline.com/{tenant-id}/v2.0
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-azure
        existingSecretKey: client_secret
```

### Authorization Setup (Azure AD manages roles)

Azure AD uses **App Roles** to scope permissions to a specific application.

**1. Define App Roles**

1. Go to your app registration -> **App roles -> Create app role**:
   - Display name: `BAMF Admin`
   - Allowed member types: Users/Groups
   - Value: `admin` (this is what BAMF sees)
   - Description: Full platform administration
2. Repeat for each role (`ssh-access`, `k8s-access`, `audit`, etc.)

**2. Assign users to App Roles**

1. Go to **Enterprise applications -> your app -> Users and groups**
2. **Add user/group -> select user -> select role -> Assign**

**3. Update BAMF config**

```yaml
auth:
  sso:
    oidc:
      azure:
        enabled: true
        displayName: "Microsoft Entra ID"
        issuerUrl: https://login.microsoftonline.com/{tenant-id}/v2.0
        clientId: YOUR_CLIENT_ID
        groupsClaim: roles  # Azure AD puts App Roles in the "roles" claim
        rolePrefixes: []    # App Role values are already plain names
        existingSecret: bamf-azure
        existingSecretKey: client_secret
```

Azure AD includes App Role values in the `roles` claim of the ID token
automatically.

---

## Keycloak

### Authentication Setup

**1. Create a client**

1. Go to **Clients -> Create client**
   - Client type: OpenID Connect
   - Client ID: `bamf`
2. Configure:
   - Valid redirect URIs: `https://bamf.example.com/api/v1/auth/callback`
   - Client authentication: On (generates a secret)

**2. Configure BAMF**

```yaml
auth:
  sso:
    oidc:
      keycloak:
        enabled: true
        displayName: "Keycloak"
        issuerUrl: https://keycloak.example.com/realms/myorg
        clientId: bamf
        existingSecret: bamf-keycloak
        existingSecretKey: client_secret
```

### Authorization Setup (Keycloak manages roles)

Keycloak uses **client-scoped roles** and **protocol mappers**.

**1. Create client roles**

1. Go to **Clients -> bamf -> Roles tab**
2. Create roles matching BAMF role names: `admin`, `ssh-access`, etc.

**2. Add a protocol mapper**

1. Go to **Clients -> bamf -> Client scopes -> bamf-dedicated -> Add mapper**
   - Mapper type: User Client Role
   - Client ID: `bamf`
   - Token Claim Name: `roles`
   - Add to ID token: On

**3. Assign roles to users**

1. Go to **Users -> select user -> Role mapping -> Assign role**
2. Filter by client -> select `bamf` -> assign roles

**4. Update BAMF config**

```yaml
auth:
  sso:
    oidc:
      keycloak:
        enabled: true
        displayName: "Keycloak"
        issuerUrl: https://keycloak.example.com/realms/myorg
        clientId: bamf
        groupsClaim: roles
        rolePrefixes: []  # Keycloak client roles are already plain names
        existingSecret: bamf-keycloak
        existingSecretKey: client_secret
```

---

## JumpCloud

### Authentication Setup (5 minutes)

This gets users logging in via JumpCloud. Roles are assigned internally in BAMF.

**1. Create a Custom OIDC Application**

1. In the JumpCloud admin console, go to **SSO** (under User Authentication)
2. Click **Add New Application**
3. Select **Custom Application**
4. Check **Manage Single Sign-On (SSO)** and click **Next**
5. Select **Configure SSO with OIDC** and click **Next**
6. Configure:
   - **Display Label**: `BAMF`
   - **Redirect URIs**: `https://bamf.example.com/api/v1/auth/callback`
   - **Client Authentication Type**: **Client Secret Basic**
   - **Login URL**: `https://bamf.example.com`
7. Under **Attribute Mapping**, enable **Standard Scopes**: Email, Profile
8. Click **Activate**
9. JumpCloud displays the **Client ID** and **Client Secret** — save both

**2. Assign user groups to the application**

1. Click the BAMF application -> **User Groups** tab
2. Select the groups whose members should have access (or "All Users")
3. Click **Save**

> **Important**: JumpCloud requires explicit group assignment. Users not in an
> assigned group cannot log in, even if they exist in JumpCloud.

**3. Configure BAMF**

```yaml
auth:
  sso:
    defaultProvider: jumpcloud
    oidc:
      jumpcloud:
        enabled: true
        displayName: "JumpCloud"
        issuerUrl: https://oauth.id.jumpcloud.com/
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-jumpcloud
        existingSecretKey: client_secret
```

```zsh
kubectl -n bamf create secret generic bamf-jumpcloud \
  --from-literal=client_secret=YOUR_CLIENT_SECRET
```

**4. Assign roles in BAMF**

After users log in, assign roles via the BAMF admin API or web UI:

```zsh
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "jumpcloud", "email": "alice@example.com", "roles": ["admin"]}'
```

### Authorization Setup (JumpCloud manages roles)

If you want JumpCloud group membership to control BAMF roles, you need to
configure attribute mapping so JumpCloud includes groups in the OIDC token.

**1. Create groups with `bamf-` prefix**

1. Go to **User Groups -> Create Group**
2. Create groups matching your BAMF roles:

| JumpCloud Group | BAMF Role (after prefix strip) |
|---|---|
| `bamf-admin` | `admin` |
| `bamf-ssh-access` | `ssh-access` |
| `bamf-k8s-access` | `k8s-access` |
| `bamf-audit` | `audit` |

3. Add users to the appropriate groups

**2. Add the group attribute to the OIDC application**

1. Go to **SSO -> your BAMF application -> SSO tab**
2. Scroll to **Attribute Mapping**
3. Check **include group attribute**
4. Enter the **Groups Attribute Name**: `groups`
5. Click **Save**

This tells JumpCloud to include the user's group memberships (for groups
assigned to this application) in the OIDC token under the `groups` claim.

**3. Assign the `bamf-` groups to the application**

1. Click the BAMF application -> **User Groups** tab
2. Select each `bamf-*` group
3. Click **Save**

Only groups assigned to the application are included in the token. If you
forget to assign a group here, its members can log in but the group won't
appear in the `groups` claim.

**4. Update BAMF config for authorization**

Add `groupsClaim` to your existing config:

```yaml
auth:
  sso:
    oidc:
      jumpcloud:
        enabled: true
        displayName: "JumpCloud"
        issuerUrl: https://oauth.id.jumpcloud.com/
        clientId: YOUR_CLIENT_ID
        groupsClaim: groups
        existingSecret: bamf-jumpcloud
        existingSecretKey: client_secret
```

### What JumpCloud sends to BAMF (with authz)

When a user in the `bamf-admin` group logs in, the token contains:

```json
{
  "iss": "https://oauth.id.jumpcloud.com/",
  "groups": ["bamf-admin"]
}
```

BAMF strips the `bamf-` prefix, yielding role `admin`.

> **Known quirk**: When a user belongs to exactly one group, JumpCloud sends
> the groups claim as a string (`"groups": "bamf-admin"`) rather than a
> single-element array. BAMF handles this automatically — no action needed.

### JumpCloud Troubleshooting

**Groups claim is empty**

1. Verify **include group attribute** is checked in the SSO tab with name
   `groups`
2. Verify the `bamf-*` groups are assigned to the application (User Groups tab)
3. Verify users are members of the `bamf-*` groups

**"User not authorized" or login fails**

JumpCloud requires users (or their groups) to be explicitly assigned to the
application. Go to **SSO -> BAMF app -> User Groups** and assign the
appropriate groups.

---

## Google

Google's OIDC implementation does not include groups or roles in tokens.
Authentication setup is all there is — roles must always be assigned in BAMF.

### Setup

**1. Create OAuth credentials**

1. Go to **Google Cloud Console -> APIs & Services -> Credentials**
2. Click **Create Credentials -> OAuth client ID -> Web application**
3. Add authorized redirect URI: `https://bamf.example.com/api/v1/auth/callback`
4. Note the **Client ID** and **Client Secret**

**2. Configure consent screen**

1. Go to **APIs & Services -> OAuth consent screen**
2. Configure for your organization (internal or external)

**3. Configure BAMF**

```yaml
auth:
  sso:
    oidc:
      google:
        enabled: true
        displayName: "Google"
        issuerUrl: https://accounts.google.com
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-google
        existingSecretKey: client_secret
```

**4. Assign roles in BAMF**

```zsh
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "google", "email": "alice@example.com", "roles": ["admin"]}'
```

> **Note**: Any Google account can authenticate (including `@gmail.com`
> accounts). You don't need Google Workspace. Since Google doesn't send
> group information, all role assignment happens in BAMF.

---

## Generic OIDC

Any OIDC-compliant provider works with BAMF. The minimum config for
authentication:

```yaml
auth:
  sso:
    oidc:
      my-provider:
        enabled: true
        displayName: "My IdP"
        issuerUrl: https://idp.example.com  # must serve /.well-known/openid-configuration
        clientId: YOUR_CLIENT_ID
        existingSecret: bamf-my-provider
        existingSecretKey: client_secret
```

To add authorization (if the provider sends groups/roles in tokens):

```yaml
        # If the provider supports API audiences (like Auth0):
        audience: https://bamf.example.com/api

        # Which claim contains groups/roles (default: "groups"):
        groupsClaim: roles

        # Override default scopes if needed:
        scopes: ["openid", "profile", "email", "groups"]

        # Prefix stripping (default: ["bamf:", "bamf-"]):
        # Set to [] if the IdP sends plain role names
        rolePrefixes: []

        # Explicit mapping if claim values don't match BAMF role names:
        claimsToRoles:
          - claim: groups
            value: platform-admins
            roles: [admin]
```

**What BAMF checks at login (in order):**

1. Access token `permissions` array (if `audience` is configured)
2. ID token claim named by `groupsClaim`
3. `/userinfo` endpoint claim named by `groupsClaim`
4. `claims_to_roles` rules against all raw claims

All results are merged. If any source provides `admin`, the user gets `admin`.

---

## Credential Management

SSO client secrets must be stored in Kubernetes Secrets, never in
`values.yaml` or ConfigMaps.

```zsh
kubectl -n bamf create secret generic bamf-auth0 \
  --from-literal=client_secret=YOUR_CLIENT_SECRET
```

Reference it in Helm values:

```yaml
auth:
  sso:
    oidc:
      auth0:
        existingSecret: bamf-auth0
        existingSecretKey: client_secret
```

The secret is injected as an environment variable (`BAMF_AUTH0_CLIENT_SECRET`)
into the API pod. The naming convention is `BAMF_{PROVIDER_NAME}_CLIENT_SECRET`
(uppercase provider name).

For providers managed via ExternalSecrets operator:

```yaml
auth:
  sso:
    oidc:
      auth0:
        externalSecret:
          enabled: true
          secretStoreRef:
            name: aws-secrets-manager
            kind: ClusterSecretStore
          remoteRef:
            key: production/bamf/auth0
            property: client_secret
```

---

## Internal Role Assignments

In addition to IdP-derived roles, BAMF admins can assign roles internally via
the API. This is useful for:

- Providers that don't support groups/roles in tokens (Google)
- Granting additional roles beyond what the IdP provides
- Pre-provisioning roles before a user's first login
- Keeping things simple — authentication-only setup + internal roles

Internal assignments are keyed by `(provider_name, email)`:

```zsh
curl -X PUT https://bamf.example.com/api/v1/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "auth0", "email": "alice@example.com", "roles": ["admin"]}'
```

At login, internally-assigned roles are merged with IdP-derived roles.
Neither source overrides the other.

---

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

---

## Multiple Providers

BAMF supports multiple providers simultaneously. Users choose their provider
at login:

```yaml
auth:
  local:
    enabled: true
  sso:
    defaultProvider: auth0
    oidc:
      auth0:
        enabled: true
        # ...
      okta:
        enabled: true
        # ...
```

The login page shows all configured providers. CLI users specify `--provider`:

```zsh
bamf login --provider auth0
bamf login --provider okta
bamf login --provider local
```

---

## Troubleshooting

### "Invalid claim 'iss'"

The issuer URL in your config doesn't match the IdP's discovery document.
BAMF uses the issuer from the discovery document for validation, so minor
differences (trailing slash) usually resolve automatically. If it persists,
verify `issuerUrl` points to the correct tenant and authorization server.

### Permissions not appearing after login

Check what BAMF received. Look at API logs for the "OIDC authentication
successful" message:

```zsh
kubectl logs -n bamf -l app.kubernetes.io/component=api | grep "OIDC authentication"
```

This shows the `groups` array BAMF extracted. If it's empty:
- Did you complete the **authorization setup** for your provider? If not,
  groups will always be empty — assign roles in BAMF instead.
- **Auth0**: Verify `audience` is set, RBAC is enabled on the API, and the
  user has permissions.
- **Okta**: See [Okta Troubleshooting](#okta-troubleshooting).
- **Azure AD**: Verify App Roles are defined and assigned.
- **Keycloak**: Verify the protocol mapper exists with "Add to ID token" on.

### Session Management

Sessions are stored in Redis (not JWTs). Admins can:
- View all active sessions: **Sessions** page in web UI
- Revoke a user's sessions: `DELETE /api/v1/auth/sessions/user/{email}`
- Session lifetime is configurable (default: 12 hours)
