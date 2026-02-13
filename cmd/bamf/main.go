// BAMF CLI - Bridge Access Management Fabric
package main

import (
	"fmt"
	"os"

	"github.com/mattrobinsonsre/bamf/cmd/bamf/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
