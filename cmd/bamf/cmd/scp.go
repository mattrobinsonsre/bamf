package cmd

import (
	"github.com/spf13/cobra"
)

var scpCmd = &cobra.Command{
	Use:   "scp [scp-flags...] <source> <destination>",
	Short: "Copy files via SCP through BAMF",
	Long: `Copy files to/from a resource via SCP through the BAMF tunnel.

Wraps the native scp client, injecting a ProxyCommand that routes the
connection through BAMF. All SCP flags are passed through unchanged.

Use [user@]resource:/path syntax for the remote side, where resource is
a BAMF resource name.

Examples:
  # Copy local file to remote
  bamf scp ./config.yaml admin@web-server-1:/etc/app/config.yaml

  # Copy remote file to local
  bamf scp admin@web-server-1:/var/log/app.log ./app.log

  # Recursive copy
  bamf scp -r ./deploy/ admin@web-server-1:/opt/app/

  # Preserve attributes
  bamf scp -p admin@web-server-1:/etc/hosts ./hosts`,
	DisableFlagParsing: true,
	RunE:               runSCP,
}

func init() {
	rootCmd.AddCommand(scpCmd)
}

func runSCP(cmd *cobra.Command, args []string) error {
	// Handle --help manually since DisableFlagParsing is set
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return cmd.Help()
		}
	}
	if len(args) == 0 {
		return cmd.Help()
	}

	return execSSHBinary("scp", args)
}
