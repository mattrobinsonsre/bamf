// Stub for non-Linux platforms (macOS, Windows). The bridge only runs in K8s
// (Linux containers), but this stub allows compilation and testing on macOS.

//go:build !linux

package webterm

import (
	"fmt"
	"os"
	"runtime"
)

// OpenPTY opens a pseudoterminal pair. Not supported outside Linux.
func OpenPTY() (master, slave *os.File, err error) {
	return nil, nil, fmt.Errorf("webterm: OpenPTY not supported on %s", runtime.GOOS)
}

// SetWinSize sets the terminal window size. Not supported outside Linux.
func SetWinSize(master *os.File, cols, rows uint16) error {
	return fmt.Errorf("webterm: SetWinSize not supported on %s", runtime.GOOS)
}
