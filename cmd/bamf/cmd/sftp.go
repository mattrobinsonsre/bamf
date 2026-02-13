package cmd

import (
	"github.com/spf13/cobra"
)

var sftpCmd = &cobra.Command{
	Use:   "sftp [sftp-flags...] [user@]<resource>",
	Short: "SFTP to a resource via BAMF",
	Long: `Start an SFTP session to a resource through the BAMF tunnel.

Wraps the native sftp client, injecting a ProxyCommand that routes the
connection through BAMF. All SFTP flags are passed through unchanged.

Examples:
  bamf sftp admin@web-server-1
  bamf sftp -b batchfile admin@web-server-1`,
	DisableFlagParsing: true,
	RunE:               runSFTP,
}

func init() {
	rootCmd.AddCommand(sftpCmd)
}

func runSFTP(cmd *cobra.Command, args []string) error {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return cmd.Help()
		}
	}
	if len(args) == 0 {
		return cmd.Help()
	}

	return execSSHBinary("sftp", args)
}
