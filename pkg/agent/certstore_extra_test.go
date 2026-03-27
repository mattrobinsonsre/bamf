package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// ── Tests: SaveCertificates to read-only directory ───────────────────

func TestFileCertStore_SaveToReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory permissions behave differently on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can write to read-only directories")
	}

	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.Mkdir(readOnlyDir, 0500))
	t.Cleanup(func() {
		// Restore write permission so t.TempDir cleanup works
		_ = os.Chmod(readOnlyDir, 0700)
	})

	// Point to a subdirectory inside the read-only dir
	store := NewFileCertStore(filepath.Join(readOnlyDir, "certs"))
	ctx := context.Background()

	err := store.SaveCertificates(ctx, []byte("cert"), []byte("key"), []byte("ca"))
	require.Error(t, err, "should fail writing to read-only directory")
}

// ── Tests: Round-trip save and load with realistic data ──────────────

func TestFileCertStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	cert := []byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUe...\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIL...\n-----END EC PRIVATE KEY-----\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nMIIBsDCCAVag...\n-----END CERTIFICATE-----\n")

	// Save
	err := store.SaveCertificates(ctx, cert, key, ca)
	require.NoError(t, err)

	// Load
	loadedCert, loadedKey, loadedCA, err := store.LoadCertificates(ctx)
	require.NoError(t, err)

	// Verify exact byte-for-byte match
	require.Equal(t, cert, loadedCert)
	require.Equal(t, key, loadedKey)
	require.Equal(t, ca, loadedCA)
}

// ── Tests: Round-trip with binary data ───────────────────────────────

func TestFileCertStore_RoundTrip_BinaryData(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// Use data with null bytes and high-byte values to test binary safety
	cert := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	key := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	ca := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	err := store.SaveCertificates(ctx, cert, key, ca)
	require.NoError(t, err)

	loadedCert, loadedKey, loadedCA, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, cert, loadedCert)
	require.Equal(t, key, loadedKey)
	require.Equal(t, ca, loadedCA)
}

// ── Tests: Overwrite existing certificates ───────────────────────────

func TestFileCertStore_Overwrite(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// Save initial certs
	err := store.SaveCertificates(ctx, []byte("cert1"), []byte("key1"), []byte("ca1"))
	require.NoError(t, err)

	// Overwrite with new certs
	err = store.SaveCertificates(ctx, []byte("cert2"), []byte("key2"), []byte("ca2"))
	require.NoError(t, err)

	// Load should return the new values
	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("cert2"), cert)
	require.Equal(t, []byte("key2"), key)
	require.Equal(t, []byte("ca2"), ca)
}

// ── Tests: HasCertificates with only key (no cert) ───────────────────

func TestFileCertStore_HasCertificates_OnlyKey(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)

	// Write only key — should return false since cert is missing
	err := os.WriteFile(store.KeyFile(), []byte("key"), 0600)
	require.NoError(t, err)

	require.False(t, store.HasCertificates(context.Background()))
}

// ── Tests: HasCertificates with both cert and key (no CA) ────────────

func TestFileCertStore_HasCertificates_CertAndKey(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)

	// Write cert and key — HasCertificates only checks cert + key, not CA
	require.NoError(t, os.WriteFile(store.CertFile(), []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(store.KeyFile(), []byte("key"), 0600))

	require.True(t, store.HasCertificates(context.Background()))
}

// ── Tests: LoadCertificates with empty files ─────────────────────────

func TestFileCertStore_Load_EmptyCertFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// Write empty cert, non-empty key and CA
	require.NoError(t, os.WriteFile(store.CertFile(), []byte{}, 0600))
	require.NoError(t, os.WriteFile(store.KeyFile(), []byte("key"), 0600))
	require.NoError(t, os.WriteFile(store.CAFile(), []byte("ca"), 0644))

	// LoadCertificates should succeed but return empty cert
	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Empty(t, cert)
	require.Equal(t, []byte("key"), key)
	require.Equal(t, []byte("ca"), ca)
}

func TestFileCertStore_Load_EmptyKeyFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	require.NoError(t, os.WriteFile(store.CertFile(), []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(store.KeyFile(), []byte{}, 0600))
	require.NoError(t, os.WriteFile(store.CAFile(), []byte("ca"), 0644))

	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("cert"), cert)
	require.Empty(t, key)
	require.Equal(t, []byte("ca"), ca)
}

func TestFileCertStore_Load_EmptyCAFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	require.NoError(t, os.WriteFile(store.CertFile(), []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(store.KeyFile(), []byte("key"), 0600))
	require.NoError(t, os.WriteFile(store.CAFile(), []byte{}, 0644))

	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("cert"), cert)
	require.Equal(t, []byte("key"), key)
	require.Empty(t, ca)
}

// ── Tests: CertFile, KeyFile, CAFile paths ───────────────────────────

func TestFileCertStore_FilePaths(t *testing.T) {
	store := NewFileCertStore("/opt/bamf/data")
	require.Equal(t, "/opt/bamf/data/agent.crt", store.CertFile())
	require.Equal(t, "/opt/bamf/data/agent.key", store.KeyFile())
	require.Equal(t, "/opt/bamf/data/ca.crt", store.CAFile())
}

func TestFileCertStore_FilePaths_TrailingSlash(t *testing.T) {
	// filepath.Join normalizes trailing slashes
	store := NewFileCertStore("/opt/bamf/data/")
	require.Equal(t, "/opt/bamf/data/agent.crt", store.CertFile())
	require.Equal(t, "/opt/bamf/data/agent.key", store.KeyFile())
	require.Equal(t, "/opt/bamf/data/ca.crt", store.CAFile())
}

// ── Tests: Save creates nested directory structure ───────────────────

func TestFileCertStore_SaveCreatesDeepNesting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c", "d")
	store := NewFileCertStore(dir)
	ctx := context.Background()

	err := store.SaveCertificates(ctx, []byte("cert"), []byte("key"), []byte("ca"))
	require.NoError(t, err)

	// Verify the deep directory was created
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	// Verify files exist and are readable
	require.True(t, store.HasCertificates(ctx))
}

// ── Tests: Save with large data ──────────────────────────────────────

func TestFileCertStore_SaveLargeData(t *testing.T) {
	dir := t.TempDir()
	store := NewFileCertStore(dir)
	ctx := context.Background()

	// 100KB of data per file (simulating large certs)
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	err := store.SaveCertificates(ctx, largeData, largeData, largeData)
	require.NoError(t, err)

	cert, key, ca, err := store.LoadCertificates(ctx)
	require.NoError(t, err)
	require.Equal(t, largeData, cert)
	require.Equal(t, largeData, key)
	require.Equal(t, largeData, ca)
}
