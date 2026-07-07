package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// contractFixture reads a golden fixture shared with the Python producer tests
// (services/tests/contracts/). The same committed file both sides validate IS
// the contract — see services/tests/test_api/test_contract_fixtures.py.
func contractFixture(t *testing.T, name string) []byte {
	t.Helper()
	// `go test` runs with the working dir set to the package dir
	// (cmd/bamf/cmd); the repo root is three levels up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Join(wd, "..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "services", "tests", "contracts", name))
	require.NoError(t, err, "shared contract fixture must exist")
	return data
}

// TestAgentsListEnvelopeContract guards the API↔CLI list-envelope contract: the
// CLI must decode the CursorPage "items" envelope and the item fields it uses.
// This is exactly the guard the "bamf agents is always empty" bug (#120) lacked
// — the Go struct decoded a different key while the Go tests stayed green.
func TestAgentsListEnvelopeContract(t *testing.T) {
	var page struct {
		Items []agent `json:"items"`
	}
	require.NoError(t, json.Unmarshal(contractFixture(t, "agents_list.json"), &page))
	require.Len(t, page.Items, 1,
		"CLI must decode the CursorPage 'items' envelope, not a bare or renamed key")

	a := page.Items[0]
	require.Equal(t, "web-prod-01", a.Name)
	require.Equal(t, "online", a.Status)
	require.Equal(t, 3, a.ResourceCount)
	require.Equal(t, "prod", a.Labels["env"])
	require.NotNil(t, a.LastHeartbeat)
}

// TestTokensListEnvelopeContract guards the same CursorPage "items" envelope for
// `bamf tokens list` — the surface #120 explicitly named alongside `bamf agents`.
// The decode struct here mirrors runTokensList in tokens.go.
func TestTokensListEnvelopeContract(t *testing.T) {
	var page struct {
		Items []joinToken `json:"items"`
	}
	require.NoError(t, json.Unmarshal(contractFixture(t, "tokens_list.json"), &page))
	require.Len(t, page.Items, 1,
		"CLI must decode the CursorPage 'items' envelope, not a bare or renamed key")

	tok := page.Items[0]
	require.Equal(t, "prod-agents", tok.Name)
	require.Equal(t, 2, tok.UseCount)
	require.False(t, tok.IsRevoked)
	require.NotNil(t, tok.MaxUses)
	require.Equal(t, 10, *tok.MaxUses)
	require.Equal(t, "prod", tok.AgentLabels["env"])
	require.False(t, tok.ExpiresAt.IsZero())
}

// TestResourcesListEnvelopeContract guards the CUSTOM "resources" envelope for
// `bamf resources`/`bamf ls` (runResources in resources.go decodes
// {"resources": [...]}, not the CursorPage "items" key). A producer rename of
// this key would silently empty the CLI the way #120 emptied `bamf agents`.
func TestResourcesListEnvelopeContract(t *testing.T) {
	var result struct {
		Resources []resource `json:"resources"`
	}
	require.NoError(t, json.Unmarshal(contractFixture(t, "resources_list.json"), &result))
	require.Len(t, result.Resources, 1,
		"CLI must decode the custom 'resources' envelope, not a bare or renamed key")

	r := result.Resources[0]
	require.Equal(t, "web-prod-01", r.Name)
	require.Equal(t, "ssh", r.ResourceType)
	require.Equal(t, "available", r.Status)
	require.Equal(t, "datacenter-agent-01", r.AgentName)
	require.Equal(t, "prod", r.Labels["env"])
}
