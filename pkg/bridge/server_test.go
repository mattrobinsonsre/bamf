package bridge

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestExtractSessionInfo(t *testing.T) {
	cert := &x509.Certificate{URIs: []*url.URL{
		mustURL("bamf://session/sess-1"),
		mustURL("bamf://resource/web-01"),
		mustURL("bamf://bridge/bridge-0"),
		mustURL("bamf://role/client"),
		mustURL("bamf://type/ssh-audit"),
	}}
	info, err := extractSessionInfo(cert)
	require.NoError(t, err)
	require.Equal(t, "sess-1", info.SessionID)
	require.Equal(t, "web-01", info.Resource)
	require.Equal(t, "bridge-0", info.BridgeID)
	require.Equal(t, "client", info.Role)
	require.Equal(t, "ssh-audit", info.ResourceType)
}

func TestExtractSessionInfo_LegacyNoType(t *testing.T) {
	cert := &x509.Certificate{URIs: []*url.URL{mustURL("bamf://session/s")}}
	info, err := extractSessionInfo(cert)
	require.NoError(t, err)
	require.Empty(t, info.ResourceType)
}

func TestExtractSessionInfo_MissingSession(t *testing.T) {
	_, err := extractSessionInfo(&x509.Certificate{URIs: nil})
	require.Error(t, err)
}

func TestShortID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short does not panic", "abc", "abc"},
		{"exactly 16", "0123456789abcdef", "0123456789abcdef"},
		{"long is truncated", "0123456789abcdef0123", "0123456789abcdef..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shortID(tt.in))
		})
	}
}

// TestResolveResourceType guards the #157 invariant: the CA-signed session cert
// is authoritative for recording/audit routing — a client cannot force an
// unrecorded splice via the wire line. Only a legacy cert with no type SAN
// falls back to the wire line.
func TestResolveResourceType(t *testing.T) {
	tests := []struct {
		name     string
		wireType string
		certType string
		want     string
	}{
		{"cert wins over wire", "ssh", "ssh-audit", "ssh-audit"},
		{"client cannot downgrade audit", "ssh", "postgres-audit", "postgres-audit"},
		{"client cannot strip audit to plain", "ssh-audit", "ssh-audit", "ssh-audit"},
		{"legacy no-type falls back to wire", "ssh-audit", "", "ssh-audit"},
		{"legacy no-type default tunnel", "tunnel", "", "tunnel"},
		{"cert wins even if wire is empty-ish", "tunnel", "web-ssh", "web-ssh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, resolveResourceType(tt.wireType, tt.certType))
		})
	}
}

// TestBridgePinMatches guards the #151 invariant: the session-cert bridge pin
// must match this bridge, and an empty pin fails closed (never matches).
func TestBridgePinMatches(t *testing.T) {
	tests := []struct {
		name         string
		certBridgeID string
		ownBridgeID  string
		want         bool
	}{
		{"matching pin", "bridge-0", "bridge-0", true},
		{"different bridge rejected", "bridge-1", "bridge-0", false},
		{"empty pin fails closed", "", "bridge-0", false},
		{"empty pin fails closed even vs empty own", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, bridgePinMatches(tt.certBridgeID, tt.ownBridgeID))
		})
	}
}

// TestCleanupPendingIdempotent covers the safety the panic-recovery cleanup
// relies on: evicting a pending session is a no-op when it's missing or already
// matched, so calling it from a deferred recover can't corrupt state.
func TestCleanupPendingIdempotent(t *testing.T) {
	s := &Server{pendingConns: make(map[string]*pendingConnection)}

	// Cleaning a session that was never registered is safe.
	s.cleanupPending("never-registered")

	// Register, clean once → gone.
	s.pendingConns["sess"] = &pendingConnection{sessionID: "sess"}
	s.cleanupPending("sess")
	require.NotContains(t, s.pendingConns, "sess")

	// Cleaning again (e.g. after a match already deleted it) is still safe.
	s.cleanupPending("sess")
	require.Empty(t, s.pendingConns)
}

func TestParseHandshakeParams(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"single", "a=b", map[string]string{"a": "b"}},
		{"multi line", "a=b\nc=d", map[string]string{"a": "b", "c": "d"}},
		{"whitespace trimmed", "  a=b  \n c=d ", map[string]string{"a": "b", "c": "d"}},
		{"line without = is skipped", "a=b\nnoeq\nc=d", map[string]string{"a": "b", "c": "d"}},
		{"only first = splits", "a=b=c", map[string]string{"a": "b=c"}},
		{"empty value", "a=", map[string]string{"a": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseHandshakeParams(tt.in))
		})
	}
}

func TestParseUint16(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  uint16
		want uint16
	}{
		{"empty falls back to default", "", 8443, 8443},
		{"valid", "443", 8443, 443},
		{"max uint16", "65535", 1, 65535},
		{"overflow by one falls back", "65536", 1, 1},
		{"large overflow falls back", "99999", 1, 1},
		{"non-numeric falls back", "abc", 1, 1},
		{"trailing non-digit falls back", "44a3", 1, 1},
		{"zero is valid", "0", 8443, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseUint16(tt.in, tt.def))
		})
	}
}

// extractSessionInfo must ignore SAN URIs that aren't ours: non-bamf schemes,
// unknown bamf hosts, and empty-path entries (a client can't smuggle routing
// state past the CA-set SANs). The last valid value for a host wins.
func TestExtractSessionInfo_IgnoresNonBamfAndUnknown(t *testing.T) {
	cert := &x509.Certificate{URIs: []*url.URL{
		mustURL("https://example.com/foo"), // non-bamf scheme → ignored
		mustURL("bamf://session/sess-1"),
		mustURL("bamf://unknown/xyz"), // unknown host → ignored
		mustURL("bamf://resource/"),   // empty path → skipped
		mustURL("bamf://resource/web-01"),
	}}

	info, err := extractSessionInfo(cert)
	require.NoError(t, err)
	require.Equal(t, "sess-1", info.SessionID)
	require.Equal(t, "web-01", info.Resource)
	require.Empty(t, info.BridgeID)
}
