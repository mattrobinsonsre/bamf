terraform {
  required_providers {
    bamf = {
      source = "mattrobinsonsre/bamf"
    }
  }
}

# endpoint + token come from BAMF_API_URL / BAMF_TOKEN
provider "bamf" {}
