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
