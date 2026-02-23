// Package tlsutil provides hardened TLS configurations for BAMF Go components.
//
// All internal mTLS connections (CLI ↔ Bridge ↔ Agent) default to TLS 1.3.
// TLS 1.2 fallback cipher suites are provided for deployments that need them.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// SecureCipherSuitesTLS12 lists the only acceptable TLS 1.2 cipher suites.
// Used only when MinVersion is explicitly set to TLS 1.2. TLS 1.3 suites
// are always secure and not configurable — Go auto-negotiates them.
//
// Excluded categories:
//   - RSA key exchange (no forward secrecy)
//   - CBC mode (padding oracle attacks)
//   - 3DES, RC4, and other legacy ciphers
var SecureCipherSuitesTLS12 = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// SecureCurvePreferences lists the allowed elliptic curves in preference order.
// X25519 is preferred (fast, constant-time). P-256 is the fallback.
var SecureCurvePreferences = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

// ParseMinVersion converts a version string ("1.2" or "1.3") to a tls constant.
// Returns tls.VersionTLS13 for unrecognized values.
func ParseMinVersion(s string) (uint16, error) {
	switch s {
	case "1.3", "":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q (must be \"1.2\" or \"1.3\")", s)
	}
}

// ServerConfig returns a hardened tls.Config for server use (bridge tunnel listener).
// minVersion should be tls.VersionTLS13 (default) or tls.VersionTLS12.
//
// The returned config uses GetCertificate for hot-swap — callers should set it
// after calling this function. ClientAuth is not set; use ServerMTLSConfig for
// mTLS listeners.
func ServerConfig(minVersion uint16) *tls.Config {
	cfg := &tls.Config{
		MinVersion:       minVersion,
		CurvePreferences: SecureCurvePreferences,
	}
	if minVersion <= tls.VersionTLS12 {
		cfg.CipherSuites = SecureCipherSuitesTLS12
	}
	return cfg
}

// ServerMTLSConfig returns a hardened tls.Config for mTLS server use.
// Requires client certificates validated against caPool.
func ServerMTLSConfig(caPool *x509.CertPool, minVersion uint16) *tls.Config {
	cfg := ServerConfig(minVersion)
	cfg.ClientCAs = caPool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg
}

// ClientConfig returns a hardened tls.Config for client use (CLI, agent).
// cert is the client certificate for mTLS. caPool validates the server.
// serverName is used for SNI.
func ClientConfig(cert tls.Certificate, caPool *x509.CertPool, serverName string, minVersion uint16) *tls.Config {
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          caPool,
		ServerName:       serverName,
		MinVersion:       minVersion,
		CurvePreferences: SecureCurvePreferences,
	}
	if minVersion <= tls.VersionTLS12 {
		cfg.CipherSuites = SecureCipherSuitesTLS12
	}
	return cfg
}
