package webterm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	// `go test` runs in the package dir (pkg/bridge/webterm); repo root is three up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..", "..")
}

// TestTerminalStatusContract guards the web-terminal handshake status vocabulary
// shared between the bridge (producer of the status frames) and the API relay
// (consumer). The golden fixture services/tests/contracts/terminal_status.json is
// validated on both sides — here against the Go constants, and in
// services/tests/test_api/test_contract_fixtures.py against terminal.py — so a
// drift in either the bridge or the relay fails its own test and forces the
// fixture (and the peer) to be updated in lockstep. This is the class of bug
// #123 hit: the bridge emitted "resumed" while the relay only accepted "ready".
func TestTerminalStatusContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "services", "tests", "contracts", "terminal_status.json"))
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

// TestTerminalStatusBrowserConsumer pins the third consumer of the status
// vocabulary — the web UI — to the same golden fixture. The browser is the one
// consumer covered by neither the Go nor the Python contract test above, so if
// the ready-status vocabulary grows, the bridge/relay/fixture could be updated
// in lockstep while the UI silently stops recognising a status (leaving the
// terminal stuck "connecting"). This reads web-terminal.tsx and asserts it
// handles exactly the fixture's ready statuses.
func TestTerminalStatusBrowserConsumer(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "services", "tests", "contracts", "terminal_status.json"))
	require.NoError(t, err)
	var fixture struct {
		ReadyStatuses []string `json:"ready_statuses"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))

	tsx, err := os.ReadFile(filepath.Join(root, "web", "src", "components", "web-terminal.tsx"))
	require.NoError(t, err, "web-terminal.tsx must exist")

	// Extract every `msg.status === '<x>'` comparison the UI branches on.
	re := regexp.MustCompile(`msg\.status === '([a-z-]+)'`)
	var handled []string
	for _, m := range re.FindAllStringSubmatch(string(tsx), -1) {
		handled = append(handled, m[1])
	}
	require.ElementsMatch(t, fixture.ReadyStatuses, handled,
		"web-terminal.tsx must handle exactly the fixture's ready statuses (update the UI when the vocabulary changes)")
}
