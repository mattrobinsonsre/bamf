package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh [ssh-flags...] [user@]<resource> [command]",
	Short: "SSH to a resource via BAMF",
	Long: `Connect to a resource via SSH through the BAMF tunnel.

Wraps the native ssh client, injecting a ProxyCommand that routes the
connection through BAMF. All SSH flags are passed through unchanged —
port forwarding, jump hosts, control sockets, and everything else works
because it IS ssh.

The resource name is used as the SSH hostname. The ProxyCommand
"bamf pipe %h" translates it into a tunnel connection.

Examples:
  # Interactive shell
  bamf ssh admin@web-server-1

  # Port forwarding
  bamf ssh -L 8080:localhost:80 admin@web-server-1

  # Remote command
  bamf ssh admin@web-server-1 uname -a

  # Verbose
  bamf ssh -v admin@web-server-1

This can also be configured manually in ~/.ssh/config:
  Host *.prod
    ProxyCommand bamf pipe %h
    UserKnownHostsFile ~/.bamf/known_hosts`,
	DisableFlagParsing: true,
	RunE:               runSSH,
}

func init() {
	rootCmd.AddCommand(sshCmd)
}

func runSSH(cmd *cobra.Command, args []string) error {
	// Handle --help manually since DisableFlagParsing is set
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return cmd.Help()
		}
	}
	if len(args) == 0 {
		return cmd.Help()
	}

	return execSSHBinary("ssh", args)
}

// execSSHBinary builds and execs an ssh or scp command with BAMF's
// ProxyCommand and UserKnownHostsFile injected. On Unix it replaces the
// current process via execReplace, handing off the TTY to the native binary.
func execSSHBinary(binary string, userArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}

	bamfPath, err := bamfDir()
	if err != nil {
		return fmt.Errorf("cannot determine bamf directory: %w", err)
	}

	proxyCmd := exe + " pipe %h %r"
	knownHosts := filepath.Join(bamfPath, "known_hosts")

	cmdArgs := []string{binary,
		"-o", "ProxyCommand=" + proxyCmd,
		"-o", "UserKnownHostsFile=" + knownHosts,
	}
	cmdArgs = append(cmdArgs, userArgs...)

	binPath, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("%s not found in PATH: %w", binary, err)
	}

	// Propagate --api flag if set, so the pipe subprocess can find the API.
	if apiURL != "" {
		os.Setenv("BAMF_API_URL", apiURL)
	}

	// Replace this process with ssh/scp — full TTY hand-off.
	return execReplace(binPath, cmdArgs, os.Environ())
}
