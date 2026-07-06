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
