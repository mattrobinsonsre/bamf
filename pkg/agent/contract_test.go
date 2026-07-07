package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTunnelCommandContract guards the API→agent dial/redial command payload.
// handleTunnelRequest reads these keys off an untyped map[string]any, so
// a producer-side key rename silently yields a nil/zero value at runtime. The
// golden services/tests/contracts/dial_command.json is emitted by the Python
// producer (agent_commands.build_tunnel_command); this asserts every key the
// agent reads resolves with the exact type it asserts on — bridge_port as a JSON
// number (float64), the rest as strings.
func TestTunnelCommandContract(t *testing.T) {
	// `go test` runs in the package dir (pkg/agent); repo root is two up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Join(wd, "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "services", "tests", "contracts", "dial_command.json"))
	require.NoError(t, err, "shared tunnel-command fixture must exist")

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	for _, k := range []string{
		"command", "session_id", "bridge_host",
		"resource_name", "session_cert", "session_key", "ca_certificate",
	} {
		v, ok := m[k].(string)
		require.Truef(t, ok, "agent reads %q as a string", k)
		require.NotEmptyf(t, v, "%q must be populated", k)
	}
	// handleTunnelRequest: data["bridge_port"].(float64)
	_, ok := m["bridge_port"].(float64)
	require.True(t, ok, "agent reads bridge_port as a JSON number (float64)")
}
