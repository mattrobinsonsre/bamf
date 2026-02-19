//go:build linux

package webterm

import (
	"os"
	"os/exec"
	"syscall"
)

// StartProcess starts a command with the given env vars attached to the given
// PTY slave as stdin/stdout/stderr. Returns the process for lifecycle management.
func StartProcess(args []string, extraEnv []string, slave *os.File) (*os.Process, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd.Process, nil
}
