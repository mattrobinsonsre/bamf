# Kubernetes Access

BAMF provides Kubernetes API access through an HTTP proxy with user
impersonation. After a one-time setup, `kubectl`, Helm, k9s, Lens, Terraform,
and any other Kubernetes tooling work without modification.

## How It Works

Unlike SSH and database access (which use TCP tunnels), Kubernetes access uses
the HTTP proxy model:

```
kubectl get pods
  └── exec credential plugin: bamf kube-credentials
  └── HTTP request ──▶ BAMF API ──▶ bridge ──▶ agent ──▶ K8s API
                        (auth, RBAC)            (impersonate user)
```

The agent authenticates to the Kubernetes API using its own ServiceAccount
and sets `Impersonate-User` / `Impersonate-Group` headers based on the user's
BAMF identity and roles.

## Setup

### 1. Ensure the Resource Exists

A Kubernetes cluster must be registered as a resource by an agent:

```yaml
# Agent config
resources:
  - name: prod-cluster
    type: kubernetes
    hostname: kubernetes.default.svc
    port: 6443
    labels:
      env: prod
```

### 2. Write kubeconfig Entry

```zsh
bamf kube login prod-cluster
```

This writes a context to `~/.kube/config` with a `bamf-` prefix:

```yaml
clusters:
- cluster:
    server: https://bamf.example.com/api/v1/kube/prod-cluster
  name: bamf-prod-cluster
users:
- name: bamf-prod-cluster
  user:
    exec:
      command: bamf
      args: [kube-credentials]
```

### 3. Use kubectl

```zsh
kubectl --context bamf-prod-cluster get pods
kubectl --context bamf-prod-cluster get namespaces

# Or set as default context
kubectl config use-context bamf-prod-cluster
kubectl get pods
```

All Kubernetes tooling works:

```zsh
# Helm
helm --kube-context bamf-prod-cluster list -A

# k9s
k9s --context bamf-prod-cluster

# Terraform
# (set KUBE_CONFIG_PATH and context in provider block)
```

## Kubernetes Groups

BAMF roles define which Kubernetes groups the user is impersonated as. This is
the mapping between BAMF identity and K8s RBAC:

```yaml
# BAMF role definition
roles:
  sre:
    allow:
      labels:
        env: [dev, staging, prod]
      kubernetes_groups:
        - system:masters        # full K8s admin

  developer:
    allow:
      labels:
        env: [dev, staging]
      kubernetes_groups:
        - developers            # needs matching ClusterRoleBinding
        - view                  # K8s built-in view ClusterRole
```

When a user has multiple roles, `kubernetes_groups` are unioned across all
matching roles. The API includes the merged group list in forwarded headers,
and the agent sets one `Impersonate-Group` header per group.

`system:masters` is a built-in K8s group with unconditional full access. For
custom groups like `developers`, the target cluster must have matching
ClusterRoleBindings.

## Agent RBAC Requirements

The agent's ServiceAccount needs permission to impersonate users and groups.
The Helm chart creates this automatically when `agent.kubernetes.impersonation.enabled=true`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
rules:
  - apiGroups: [""]
    resources: ["users", "groups", "serviceaccounts"]
    verbs: ["impersonate"]
```

## Security Model

- **BAMF controls who can reach the cluster** — authentication and RBAC
  resource access check happen at the API proxy layer.
- **K8s controls what they can do** — K8s RBAC evaluates against the
  impersonated groups. BAMF roles define which groups a user gets.
- **The agent SA is privileged** — it can impersonate anyone. It never leaves
  the cluster. The agent authenticates using the projected SA token.
- **Per-request audit** — every K8s API request is logged in the BAMF audit
  log with the user's identity.

## Troubleshooting

**"Forbidden" from kubectl** — Check that your BAMF role includes
`kubernetes_groups` that have corresponding ClusterRoleBindings in the target
cluster.

**"Unauthorized"** — Run `bamf login` to refresh your session. The exec
credential plugin reads from your cached BAMF session.

**"No such resource"** — Verify the Kubernetes resource is registered by an
agent. Check the Agents page in the web UI.
