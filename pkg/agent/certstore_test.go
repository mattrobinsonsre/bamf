package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewFileCertStore(t *testing.T) {
	store := NewFileCertStore("/tmp/test-agent")
	require.Equal(t, "/tmp/test-agent/agent.crt", store.CertFile())
	require.Equal(t, "/tmp/test-agent/agent.key", store.KeyFile())
	require.Equal(t, "/tmp/test-agent/ca.crt", store.CAFile())
}

func TestFileCertStore_HasCertificates_Empty(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	require.False(t, store.HasCertificates(context.Background()))
}

func TestFileCertStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	certData := []byte("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
	keyData := []byte("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")
	caData := []byte("-----BEGIN CERTIFICATE-----\nFAKE CA\n-----END CERTIFICATE-----\n")

	err := store.SaveCertificates(ctx, certData, keyData, caData)
	require.NoError(t, err)

	// Files should exist
	require.True(t, store.HasCertificates(ctx))

	// Load them back
	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, certData, cert)
	require.Equal(t, keyData, key)
	require.Equal(t, caData, ca)
}

func TestFileCertStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	err := store.SaveCertificates(ctx, []byte("cert"), []byte("key"), []byte("ca"))
	require.NoError(t, err)

	// Key and cert should be 0600
	certInfo, err := os.Stat(store.CertFile())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(store.KeyFile())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())

	// CA should be 0644
	caInfo, err := os.Stat(store.CAFile())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0644), caInfo.Mode().Perm())
}

func TestFileCertStore_SaveCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deep")
	store := NewFileCertStore(dir)
	ctx := context.Background()

	err := store.SaveCertificates(ctx, []byte("cert"), []byte("key"), []byte("ca"))
	require.NoError(t, err)
	require.True(t, store.HasCertificates(ctx))
}

func TestFileCertStore_LoadMissingCert(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	_, _, _, err := store.LoadCertificates(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
}

func TestFileCertStore_LoadMissingKey(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// Write only cert
	err := os.WriteFile(store.CertFile(), []byte("cert"), 0600)
	require.NoError(t, err)

	_, _, _, err = store.LoadCertificates(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key")
}

func TestFileCertStore_LoadMissingCA(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// Write cert and key but not CA
	err := os.WriteFile(store.CertFile(), []byte("cert"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(store.KeyFile(), []byte("key"), 0600)
	require.NoError(t, err)

	_, _, _, err = store.LoadCertificates(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CA")
}

func TestFileCertStore_HasCertificates_OnlyCert(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)

	// Write only cert — should return false since key is missing
	err := os.WriteFile(store.CertFile(), []byte("cert"), 0600)
	require.NoError(t, err)

	require.False(t, store.HasCertificates(context.Background()))
}
