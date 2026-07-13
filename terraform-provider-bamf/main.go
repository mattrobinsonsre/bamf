// terraform-provider-bamf lets you manage a BAMF deployment (roles, RBAC, …)
// as code through its REST API.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/mattrobinsonsre/terraform-provider-bamf/internal/provider"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/mattrobinsonsre/bamf",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
