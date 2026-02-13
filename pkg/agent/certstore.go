package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// CertStore abstracts certificate storage for the agent.
// Implementations handle reading/writing certs to filesystem or Kubernetes Secrets.
type CertStore interface {
	// HasCertificates returns true if certificates exist in the store.
	HasCertificates(ctx context.Context) bool

	// LoadCertificates loads cert, key, and CA from the store.
	LoadCertificates(ctx context.Context) (cert, key, ca []byte, err error)

	// SaveCertificates saves cert, key, and CA to the store.
	SaveCertificates(ctx context.Context, cert, key, ca []byte) error

	// CertFile returns the path to the certificate file for TLS loading.
	CertFile() string

	// KeyFile returns the path to the key file for TLS loading.
	KeyFile() string

	// CAFile returns the path to the CA file for TLS loading.
	CAFile() string
}

// FileCertStore stores certificates on the filesystem.
// Used for non-Kubernetes deployments (VMs, bare metal).
type FileCertStore struct {
	certFile string
	keyFile  string
	caFile   string
}

// NewFileCertStore creates a filesystem-based certificate store.
func NewFileCertStore(dataDir string) *FileCertStore {
	return &FileCertStore{
		certFile: filepath.Join(dataDir, "agent.crt"),
		keyFile:  filepath.Join(dataDir, "agent.key"),
		caFile:   filepath.Join(dataDir, "ca.crt"),
	}
}

func (s *FileCertStore) HasCertificates(ctx context.Context) bool {
	_, certErr := os.Stat(s.certFile)
	_, keyErr := os.Stat(s.keyFile)
	return certErr == nil && keyErr == nil
}

func (s *FileCertStore) LoadCertificates(ctx context.Context) (cert, key, ca []byte, err error) {
	cert, err = os.ReadFile(s.certFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	key, err = os.ReadFile(s.keyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read key: %w", err)
	}

	ca, err = os.ReadFile(s.caFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	return cert, key, ca, nil
}

func (s *FileCertStore) SaveCertificates(ctx context.Context, cert, key, ca []byte) error {
	// Ensure directory exists
	dir := filepath.Dir(s.certFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	if err := os.WriteFile(s.certFile, cert, 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	if err := os.WriteFile(s.keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}
	if err := os.WriteFile(s.caFile, ca, 0644); err != nil {
		return fmt.Errorf("failed to save CA: %w", err)
	}

	return nil
}

// CertFile returns the path to the certificate file (for TLS loading).
func (s *FileCertStore) CertFile() string { return s.certFile }

// KeyFile returns the path to the key file (for TLS loading).
func (s *FileCertStore) KeyFile() string { return s.keyFile }

// CAFile returns the path to the CA file (for TLS loading).
func (s *FileCertStore) CAFile() string { return s.caFile }
