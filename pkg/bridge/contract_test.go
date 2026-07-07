package bridge

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSessionCertSANContract guards the session-cert SAN contract (the bridge's
// sole authorization input). The fixture services/tests/contracts/session_cert.pem
// is a REAL cert issued by the Python CA (ca.issue_session_certificate); the
// bridge's extractSessionInfo must read all 5 bamf:// SANs from it. Paired with
// the producer assertions in services/tests/test_api/test_contract_fixtures.py —
// a SAN-format drift fails one side and forces the fixture (and the other side)
// to be updated in lockstep.
func TestSessionCertSANContract(t *testing.T) {
	// `go test` runs in the package dir (pkg/bridge); repo root is two up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Join(wd, "..", "..")
	pemBytes, err := os.ReadFile(filepath.Join(root, "services", "tests", "contracts", "session_cert.pem"))
	require.NoError(t, err, "shared session-cert fixture must exist")

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "fixture must be a PEM certificate block")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	info, err := extractSessionInfo(cert)
	require.NoError(t, err)
	require.Equal(t, "sess-fixture-0001", info.SessionID)
	require.Equal(t, "web-01", info.Resource)
	require.Equal(t, "bamf-bridge-0", info.BridgeID)
	require.Equal(t, "client", info.Role)
	require.Equal(t, "ssh-audit", info.ResourceType)
}
