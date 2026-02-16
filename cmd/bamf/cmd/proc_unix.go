//go:build !windows

package cmd

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// detachSysProcAttr returns SysProcAttr that detaches the child into its own
// session (Setsid), so it survives the parent exiting. Unix-only.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// execGroupSysProcAttr returns SysProcAttr that puts the child in its own
// process group, allowing the entire group to be signaled. Unix-only.
func execGroupSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGTERM to the process group led by the given command.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

// ignoreSIGHUP ignores SIGHUP so the daemon child survives terminal close.
func ignoreSIGHUP() {
	signal.Ignore(syscall.SIGHUP)
}

// notifySignals registers SIGINT and SIGTERM for graceful shutdown.
func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
}

// execReplace replaces the current process with the given binary. On Unix
// this uses syscall.Exec for full TTY hand-off.
func execReplace(binPath string, args []string, env []string) error {
	return syscall.Exec(binPath, args, env)
}
