//go:build windows

package cmd

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// detachSysProcAttr returns nil on Windows — no session detach equivalent.
func detachSysProcAttr() *syscall.SysProcAttr {
	return nil
}

// execGroupSysProcAttr returns nil on Windows — no process group equivalent.
func execGroupSysProcAttr() *syscall.SysProcAttr {
	return nil
}

// killProcessGroup is a no-op on Windows — process groups work differently.
func killProcessGroup(_ *exec.Cmd) {}

// ignoreSIGHUP is a no-op on Windows — no SIGHUP signal.
func ignoreSIGHUP() {}

// notifySignals registers os.Interrupt for graceful shutdown on Windows.
func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

// execReplace runs the given binary and exits with its status code. Windows
// does not support syscall.Exec, so we spawn a child and wait.
func execReplace(binPath string, args []string, env []string) error {
	cmd := exec.Command(binPath, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil
}
