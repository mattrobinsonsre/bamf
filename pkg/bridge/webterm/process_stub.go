//go:build !linux

package webterm

import (
	"fmt"
	"os"
	"runtime"
)

// StartProcess is not supported outside Linux.
func StartProcess(args []string, extraEnv []string, slave *os.File) (*os.Process, error) {
	return nil, fmt.Errorf("webterm: StartProcess not supported on %s", runtime.GOOS)
}
