# terraform-provider-bamf

A [Terraform](https://www.terraform.io/) / [OpenTofu](https://opentofu.org/)
provider for [BAMF](https://github.com/mattrobinsonsre/bamf) — manage RBAC roles
(and, over time, join tokens, local users, and role assignments) as code through
BAMF's REST API.

> **Status: spike / prototype.** One resource (`bamf_role`) is implemented and
> verified end-to-end (create/read/update/delete + import) against a live BAMF
> stack. See [Roadmap](#roadmap). When promoted, this moves to its own
> `terraform-provider-bamf` repository for Terraform Registry publishing.

## Provider configuration

```hcl
terraform {
  required_providers {
    bamf = {
      source = "mattrobinsonsre/bamf"
    }
  }
}

provider "bamf" {
  endpoint = "https://bamf.example.com" # or $BAMF_API_URL
  # token  = "..."                      # or $BAMF_TOKEN (prefer the env var)
}
```

| Setting    | Env          | Notes |
|------------|--------------|-------|
| `endpoint` | `BAMF_API_URL` | BAMF API base URL. |
| `token`    | `BAMF_TOKEN`   | **Admin** session token (as issued by `bamf login`). Sensitive — prefer the environment variable so it isn't written to state. |

## Resources

### `bamf_role`

```hcl
resource "bamf_role" "developer" {
  name        = "developer"
  description = "Managed by Terraform"

  allow = {
    labels = { env = ["dev", "staging"] }
    names  = ["prod-debug-jumpbox"]
  }
  deny = {
    names = ["staging-secrets-db"]
  }

  kubernetes_groups = ["developers", "view"]
}
```

Import an existing role by name:

```sh
terraform import bamf_role.developer developer
```

Built-in roles (`admin`, `audit`, `everyone`) are defined in BAMF's code and
cannot be managed here.

## Local development

Build the provider and point Terraform at it with a dev override:

```sh
go build -o /tmp/tfbin/terraform-provider-bamf .

cat > dev.tfrc <<EOF
provider_installation {
  dev_overrides { "registry.terraform.io/mattrobinsonsre/bamf" = "/tmp/tfbin" }
  direct {}
}
EOF

export TF_CLI_CONFIG_FILE=$PWD/dev.tfrc
export BAMF_API_URL=https://bamf.local
export BAMF_TOKEN=<admin session token>
terraform plan   # dev_overrides skips `terraform init`
```

Run the unit tests with `go test ./...`.

## Roadmap

Candidate resources: `bamf_role_assignment`, `bamf_user` (local),
`bamf_join_token`, `bamf_resource`, `bamf_outpost_token`. Candidate data
sources: `bamf_ca_certificate`, `bamf_role`. Release via GoReleaser
(GPG-signed checksums + registry manifest) on semver tags, published to the
Terraform Registry.
