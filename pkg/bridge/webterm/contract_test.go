package webterm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTerminalStatusContract guards the web-terminal handshake status vocabulary
// shared between the bridge (producer of the status frames) and the API relay
// (consumer). The golden fixture services/tests/contracts/terminal_status.json is
// validated on both sides — here against the Go constants, and in
// services/tests/test_api/test_contract_fixtures.py against terminal.py — so a
// drift in either the bridge or the relay fails its own test and forces the
// fixture (and the peer) to be updated in lockstep. This is the class of bug
// #123 hit: the bridge emitted "resumed" while the relay only accepted "ready".
func TestTerminalStatusContract(t *testing.T) {
	// `go test` runs in the package dir (pkg/bridge/webterm); repo root is three up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Join(wd, "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "services", "tests", "contracts", "terminal_status.json"))
	require.NoError(t, err, "shared terminal-status fixture must exist")

	var fixture struct {
		AuthRequired  string   `json:"auth_required"`
		ReadyStatuses []string `json:"ready_statuses"`
		ErrorPrefix   string   `json:"error_prefix"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))

	// The bridge's status constants must match the shared fixture exactly.
	require.Equal(t, fixture.AuthRequired, StatusAuthRequired,
		"bridge auth-required constant must match the shared fixture")
	require.ElementsMatch(t, []string{StatusReady, StatusResumed}, fixture.ReadyStatuses,
		"bridge ready-status constants must match the shared fixture")
	require.Equal(t, fixture.ErrorPrefix, StatusErrorPrefix,
		"bridge error prefix must match the shared fixture")
}
