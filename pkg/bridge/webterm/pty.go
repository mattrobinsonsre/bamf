// PTY management for web terminal database sessions.
//
// Uses golang.org/x/sys/unix directly — no CGo, no external pty library.
// Only needs to work on Linux (bridge runs in K8s).

//go:build linux

package webterm

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenPTY opens a pseudoterminal pair and returns the master and slave files.
func OpenPTY() (master, slave *os.File, err error) {
	// Open the master side via /dev/ptmx.
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}

	// Unlock the slave (grantpt is a no-op on Linux devpts).
	unlock := 0
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, unlock); err != nil {
		unix.Close(masterFD)
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}

	// Get slave PTY number via TIOCGPTN ioctl.
	// TIOCGPTN writes an unsigned int to the provided pointer.
	var ptsNum uint32
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(masterFD),
		unix.TIOCGPTN,
		uintptr(unsafe.Pointer(&ptsNum)),
	)
	if errno != 0 {
		unix.Close(masterFD)
		return nil, nil, fmt.Errorf("TIOCGPTN: %w", errno)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptsNum)

	// Open slave.
	slaveFD, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		unix.Close(masterFD)
		return nil, nil, fmt.Errorf("open %s: %w", slavePath, err)
	}

	master = os.NewFile(uintptr(masterFD), "/dev/ptmx")
	slave = os.NewFile(uintptr(slaveFD), slavePath)
	return master, slave, nil
}

// SetWinSize sets the terminal window size on a PTY master.
func SetWinSize(master *os.File, cols, rows uint16) error {
	ws := unix.Winsize{
		Col: cols,
		Row: rows,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		master.Fd(),
		unix.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
