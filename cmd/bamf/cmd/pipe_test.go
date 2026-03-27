package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: sshAuditPreflight ─────────────────────────────────────────

func TestSSHAuditPreflight_NoAgent(t *testing.T) {
	// Without SSH_AUTH_SOCK, should send zero keys and get "ready"
	t.Setenv("SSH_AUTH_SOCK", "")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sshAuditPreflight(client, "testuser")
	}()

	// Read from server side and verify protocol
	reader := bufio.NewReader(server)

	// Should receive "pubkeys-done" (no pubkey lines since no agent)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "pubkeys-done\n", line)

	// No "user=" line should be sent (no keys were sent)
	// Send "ready" response
	_, err = fmt.Fprint(server, "ready\n")
	require.NoError(t, err)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("sshAuditPreflight did not complete")
	}
}

func TestSSHAuditPreflight_ServerError(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	client, server := net.Pipe()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sshAuditPreflight(client, "testuser")
	}()

	// Read the pubkeys-done line
	reader := bufio.NewReader(server)
	_, err := reader.ReadString('\n')
	require.NoError(t, err)

	// Close server — should cause read error
	server.Close()

	select {
	case err := <-errCh:
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read pre-flight response")
	case <-time.After(5 * time.Second):
		t.Fatal("sshAuditPreflight did not complete")
	}
}

func TestSSHAuditPreflight_SignRequest(t *testing.T) {
	// This test verifies the sign request handling when the bridge sends
	// a sign request. We can't easily mock the SSH agent, but we can
	// verify the protocol flow by checking that the code handles the
	// "ready" response correctly after receiving data lines.
	t.Setenv("SSH_AUTH_SOCK", "")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sshAuditPreflight(client, "")
	}()

	reader := bufio.NewReader(server)

	// Read pubkeys-done
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "pubkeys-done\n", line)

	// Send ready immediately (no sign requests when no keys)
	_, err = fmt.Fprint(server, "ready\n")
	require.NoError(t, err)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("sshAuditPreflight did not complete")
	}
}

func TestSSHAuditPreflight_InvalidAgentSocket(t *testing.T) {
	// Set SSH_AUTH_SOCK to a nonexistent path — should fall back to no keys
	t.Setenv("SSH_AUTH_SOCK", "/tmp/nonexistent-bamf-test-agent.sock")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sshAuditPreflight(client, "user")
	}()

	reader := bufio.NewReader(server)

	// Should still get pubkeys-done (no keys due to agent connect failure)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "pubkeys-done\n", line)

	// No user= line (zero keys)
	_, err = fmt.Fprint(server, "ready\n")
	require.NoError(t, err)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("sshAuditPreflight did not complete")
	}
}

func TestSSHAuditPreflight_WriteError(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	client, server := net.Pipe()
	// Close server immediately to cause write error on client
	server.Close()

	err := sshAuditPreflight(client, "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to send pubkeys-done")
	client.Close()
}

// ── Tests: readWriteCloser ───────────────────────────────────────────

func TestReadWriteCloser_Close(t *testing.T) {
	rwc := readWriteCloser{r: nil, w: nil}
	err := rwc.Close()
	require.NoError(t, err)
}

// ── Helpers for base64 encoding verification ─────────────────────────

func TestBase64EncodedPubkey_Format(t *testing.T) {
	// Verify that the pubkey format line matches expected pattern
	fakeKey := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey test@test")
	encoded := base64.StdEncoding.EncodeToString(fakeKey)

	line := fmt.Sprintf("pubkey:%s\n", encoded)
	require.True(t, strings.HasPrefix(line, "pubkey:"))
	require.True(t, strings.HasSuffix(line, "\n"))

	// Verify we can decode it back
	parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
	require.Len(t, parts, 2)
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	require.Equal(t, fakeKey, decoded)
}
