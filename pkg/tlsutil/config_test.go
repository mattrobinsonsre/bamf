package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseMinVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"1.3", tls.VersionTLS13, false},
		{"1.2", tls.VersionTLS12, false},
		{"", tls.VersionTLS13, false},   // empty defaults to 1.3
		{"1.1", 0, true},                // unsupported
		{"1.0", 0, true},                // unsupported
		{"garbage", 0, true},            // invalid
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseMinVersion(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestServerConfig(t *testing.T) {
	t.Run("TLS 1.3 default", func(t *testing.T) {
		cfg := ServerConfig(tls.VersionTLS13)
		require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
		require.Nil(t, cfg.CipherSuites, "TLS 1.3 should not set cipher suites")
		require.Equal(t, SecureCurvePreferences, cfg.CurvePreferences)
		require.Equal(t, tls.NoClientCert, cfg.ClientAuth)
	})

	t.Run("TLS 1.2 fallback sets cipher suites", func(t *testing.T) {
		cfg := ServerConfig(tls.VersionTLS12)
		require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
		require.Equal(t, SecureCipherSuitesTLS12, cfg.CipherSuites)
		require.Equal(t, SecureCurvePreferences, cfg.CurvePreferences)
	})
}

func TestServerMTLSConfig(t *testing.T) {
	caPool := x509.NewCertPool()

	cfg := ServerMTLSConfig(caPool, tls.VersionTLS13)
	require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	require.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	require.Equal(t, caPool, cfg.ClientCAs)
}

func TestClientConfig(t *testing.T) {
	cert, caPool := generateTestCert(t)

	cfg := ClientConfig(cert, caPool, "bridge.example.com", tls.VersionTLS13)
	require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	require.Len(t, cfg.Certificates, 1)
	require.Equal(t, caPool, cfg.RootCAs)
	require.Equal(t, "bridge.example.com", cfg.ServerName)
	require.Nil(t, cfg.CipherSuites, "TLS 1.3 should not set cipher suites")

	cfg12 := ClientConfig(cert, caPool, "bridge.example.com", tls.VersionTLS12)
	require.Equal(t, SecureCipherSuitesTLS12, cfg12.CipherSuites)
}

func TestSecureCipherSuites(t *testing.T) {
	// Verify all configured suites are in Go's list of secure cipher suites.
	secureSuites := make(map[uint16]bool)
	for _, s := range tls.CipherSuites() {
		secureSuites[s.ID] = true
	}

	for _, id := range SecureCipherSuitesTLS12 {
		require.True(t, secureSuites[id],
			"cipher suite 0x%04x is not in Go's secure list", id)
	}

	// Verify no insecure suites are included.
	insecureSuites := make(map[uint16]bool)
	for _, s := range tls.InsecureCipherSuites() {
		insecureSuites[s.ID] = true
	}

	for _, id := range SecureCipherSuitesTLS12 {
		require.False(t, insecureSuites[id],
			"cipher suite 0x%04x is in Go's insecure list", id)
	}
}

// generateTestCert creates a self-signed cert+key pair and CA pool for testing.
func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	return cert, pool
}
