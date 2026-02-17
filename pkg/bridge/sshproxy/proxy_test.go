package sshproxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// connPair creates a pair of connected TCP connections (avoids net.Pipe()
// deadlock with SSH's write-then-read version exchange).
func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var sConn net.Conn
	var sErr error
	done := make(chan struct{})
	go func() {
		sConn, sErr = ln.Accept()
		close(done)
	}()

	cConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	<-done
	require.NoError(t, sErr)
	return cConn, sConn
}

// testSSHServer runs a minimal SSH server that accepts any auth, opens a
// session channel, and echoes back everything it receives (prefixed with
// "echo: "). This simulates a target sshd.
func testSSHServer(t *testing.T, conn net.Conn) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		t.Logf("test SSH server: handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}

		// Handle channel requests.
		go func() {
			for req := range requests {
				switch req.Type {
				case "pty-req", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					// Echo mode: read from stdin, write "echo: " + data to stdout.
					go func() {
						buf := make([]byte, 1024)
						for {
							n, err := ch.Read(buf)
							if n > 0 {
								fmt.Fprintf(ch, "echo: %s", buf[:n])
							}
							if err != nil {
								break
							}
						}
						// Send exit-status 0.
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						ch.Close()
					}()
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					// For exec, just write the command back and exit.
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					fmt.Fprintf(ch, "exec: %s\n", payload.Command)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					ch.Close()
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func TestProxy_BasicSession(t *testing.T) {
	logger := slog.Default()

	// Create proxy.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(signer, logger)

	// Create connected pairs: client ↔ proxy, proxy ↔ target.
	clientConn, proxyClientConn := connPair(t)
	proxyTargetConn, targetConn := connPair(t)

	// Start target SSH server.
	go testSSHServer(t, targetConn)

	// Run proxy in background.
	var result *SessionResult
	var proxyErr error
	var proxyDone sync.WaitGroup
	proxyDone.Add(1)
	go func() {
		defer proxyDone.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, proxyErr = proxy.Handle(ctx, proxyClientConn, proxyTargetConn, "test-session-id-1234567890")
	}()

	// Connect as SSH client through the proxy (password auth forwarded to target).
	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientSSH, clientChans, clientReqs, err := ssh.NewClientConn(clientConn, "proxy", clientConfig)
	require.NoError(t, err)

	client := ssh.NewClient(clientSSH, clientChans, clientReqs)
	defer client.Close()

	// Open session channel.
	session, err := client.NewSession()
	require.NoError(t, err)

	// Request PTY.
	err = session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{})
	require.NoError(t, err)

	// Get stdin/stdout pipes.
	stdin, err := session.StdinPipe()
	require.NoError(t, err)
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)

	// Start shell.
	err = session.Shell()
	require.NoError(t, err)

	// Write to stdin, read the echo from stdout.
	_, err = stdin.Write([]byte("hello\n"))
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, err := stdout.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "echo: hello")

	// Close session.
	stdin.Close()
	session.Close()
	client.Close()

	// Wait for proxy to finish.
	proxyDone.Wait()
	require.NoError(t, proxyErr)
	require.NotNil(t, result)

	// Verify recording.
	recording := string(result.Recording)
	lines := strings.Split(strings.TrimSpace(recording), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "should have header + at least one output event")

	// Verify header.
	var header asciicastHeader
	err = json.Unmarshal([]byte(lines[0]), &header)
	require.NoError(t, err)
	require.Equal(t, 2, header.Version)
	require.Equal(t, 80, header.Width)
	require.Equal(t, 24, header.Height)
	require.Equal(t, "xterm-256color", header.Env["TERM"])

	// Verify at least one output event contains the echo.
	foundEcho := false
	for _, line := range lines[1:] {
		var event []any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if len(event) == 3 {
			if data, ok := event[2].(string); ok && strings.Contains(data, "echo: hello") {
				foundEcho = true
				break
			}
		}
	}
	require.True(t, foundEcho, "recording should contain the echoed output")
}

func TestProxy_ExecCommand(t *testing.T) {
	logger := slog.Default()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(signer, logger)

	clientConn, proxyClientConn := connPair(t)
	proxyTargetConn, targetConn := connPair(t)

	go testSSHServer(t, targetConn)

	var result *SessionResult
	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, proxyErr = proxy.Handle(ctx, proxyClientConn, proxyTargetConn, "test-session-exec-1234567890")
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientSSH, clientChans, clientReqs, err := ssh.NewClientConn(clientConn, "proxy", clientConfig)
	require.NoError(t, err)

	client := ssh.NewClient(clientSSH, clientChans, clientReqs)

	session, err := client.NewSession()
	require.NoError(t, err)

	// Request PTY so the recording starts.
	err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	require.NoError(t, err)

	output, err := session.Output("uptime")
	require.NoError(t, err)
	require.Contains(t, string(output), "exec: uptime")

	session.Close()
	client.Close()

	wg.Wait()
	require.NoError(t, proxyErr)
	require.NotNil(t, result)
	require.Greater(t, len(result.Recording), 0)
}

func TestProxy_HandshakeFailure(t *testing.T) {
	logger := slog.Default()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(signer, logger)

	clientConn, proxyClientConn := connPair(t)
	_, proxyTargetConn := connPair(t)

	// Write garbage instead of SSH handshake.
	go func() {
		_, _ = clientConn.Write([]byte("not an SSH handshake\r\n"))
		clientConn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, proxyErr := proxy.Handle(ctx, proxyClientConn, proxyTargetConn, "test-fail-session-1234567890")
	require.Error(t, proxyErr)
	require.Contains(t, proxyErr.Error(), "client SSH handshake failed")
}

func TestNewProxy(t *testing.T) {
	proxy, err := NewProxy(slog.Default())
	require.NoError(t, err)
	require.NotNil(t, proxy)
	require.NotNil(t, proxy.hostSigner)
}

func TestParsePtyReq(t *testing.T) {
	// Build a pty-req payload.
	payload := ssh.Marshal(struct {
		Term     string
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
		Modes    string
	}{
		Term:   "xterm-256color",
		Width:  120,
		Height: 40,
	})

	pty, err := parsePtyReq(payload)
	require.NoError(t, err)
	require.Equal(t, "xterm-256color", pty.Term)
	require.Equal(t, uint32(120), pty.Width)
	require.Equal(t, uint32(40), pty.Height)
}

func TestParseWindowChange(t *testing.T) {
	payload := ssh.Marshal(struct {
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
	}{
		Width:  200,
		Height: 50,
	})

	wc, err := parseWindowChange(payload)
	require.NoError(t, err)
	require.Equal(t, uint32(200), wc.Width)
	require.Equal(t, uint32(50), wc.Height)
}

func TestProxy_ExecNoPTY(t *testing.T) {
	// Verify that exec without PTY still produces a recording (EnsureStarted).
	// This prevents bypassing audit by avoiding PTY allocation.
	logger := slog.Default()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(signer, logger)

	clientConn, proxyClientConn := connPair(t)
	proxyTargetConn, targetConn := connPair(t)

	go testSSHServer(t, targetConn)

	var result *SessionResult
	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, proxyErr = proxy.Handle(ctx, proxyClientConn, proxyTargetConn, "test-session-nopty-1234567890")
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientSSH, clientChans, clientReqs, err := ssh.NewClientConn(clientConn, "proxy", clientConfig)
	require.NoError(t, err)

	client := ssh.NewClient(clientSSH, clientChans, clientReqs)

	session, err := client.NewSession()
	require.NoError(t, err)

	// Exec WITHOUT requesting a PTY — simulates `ssh user@host "command"`.
	output, err := session.Output("whoami")
	require.NoError(t, err)
	require.Contains(t, string(output), "exec: whoami")

	session.Close()
	client.Close()

	wg.Wait()
	require.NoError(t, proxyErr)
	require.NotNil(t, result)

	// Recording must be non-empty even without PTY.
	recording := string(result.Recording)
	lines := strings.Split(strings.TrimSpace(recording), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "should have header + at least one output event")

	// Verify header uses default dimensions (80x24) since no pty-req was sent.
	var header asciicastHeader
	err = json.Unmarshal([]byte(lines[0]), &header)
	require.NoError(t, err)
	require.Equal(t, 2, header.Version)
	require.Equal(t, 80, header.Width)
	require.Equal(t, 24, header.Height)

	// Verify the exec output was recorded.
	foundExec := false
	for _, line := range lines[1:] {
		var event []any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if len(event) == 3 {
			if data, ok := event[2].(string); ok && strings.Contains(data, "exec: whoami") {
				foundExec = true
				break
			}
		}
	}
	require.True(t, foundExec, "recording should contain exec output even without PTY")
}


// testSSHServerWithPubKey runs a minimal SSH server that authenticates
// via public key (matching the provided authorized key). Used for
// testing the remote signing / HandlePreAuth path.
func testSSHServerWithPubKey(t *testing.T, conn net.Conn, authorizedKey ssh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorizedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	config.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		t.Logf("test SSH server (pubkey): handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}

		go func() {
			for req := range requests {
				switch req.Type {
				case "pty-req", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					fmt.Fprintf(ch, "exec: %s\n", payload.Command)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					ch.Close()
				case "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					go func() {
						buf := make([]byte, 1024)
						for {
							n, err := ch.Read(buf)
							if n > 0 {
								fmt.Fprintf(ch, "echo: %s", buf[:n])
							}
							if err != nil {
								break
							}
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						ch.Close()
					}()
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func TestSignChannel_ReadPublicKeys(t *testing.T) {
	// Test the pre-flight public key exchange protocol.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	pubKey := signer.PublicKey()

	bridgeSide, cliSide := connPair(t)

	reader := bufio.NewReader(bridgeSide)
	signCh := NewSignChannel(reader, bridgeSide, slog.Default())

	// CLI goroutine: send one public key, then pubkeys-done.
	go func() {
		encoded := base64.StdEncoding.EncodeToString(pubKey.Marshal())
		fmt.Fprintf(cliSide, "pubkey:%s\n", encoded)
		fmt.Fprintf(cliSide, "pubkeys-done\n")
	}()

	err = signCh.ReadPublicKeys()
	require.NoError(t, err)
	require.True(t, signCh.HasKeys())

	signers := signCh.Signers()
	require.Len(t, signers, 1)
	require.Equal(t, string(pubKey.Marshal()), string(signers[0].PublicKey().Marshal()))

	// Test SendReady — read it on the CLI side.
	readyCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 100)
		n, _ := cliSide.Read(buf)
		readyCh <- string(buf[:n])
	}()
	err = signCh.SendReady()
	require.NoError(t, err)
	require.Equal(t, "ready\n", <-readyCh)
}

func TestSignChannel_NoKeys(t *testing.T) {
	// Use connected TCP pair for bidirectional communication.
	bridgeSide, cliSide := connPair(t)

	reader := bufio.NewReader(bridgeSide)
	signCh := NewSignChannel(reader, bridgeSide, slog.Default())

	// CLI sends zero keys.
	go func() {
		fmt.Fprintf(cliSide, "pubkeys-done\n")
	}()

	err := signCh.ReadPublicKeys()
	require.NoError(t, err)
	require.False(t, signCh.HasKeys())
	require.Len(t, signCh.Signers(), 0)
}

func TestSignChannel_SignRequest(t *testing.T) {
	// Test the full sign request/response protocol.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	pubKey := signer.PublicKey()

	bridgeSide, cliSide := connPair(t)

	reader := bufio.NewReader(bridgeSide)
	signCh := NewSignChannel(reader, bridgeSide, slog.Default())

	// CLI goroutine: send pubkey, then handle sign requests.
	go func() {
		cliReader := bufio.NewReader(cliSide)

		// Send public key.
		encoded := base64.StdEncoding.EncodeToString(pubKey.Marshal())
		fmt.Fprintf(cliSide, "pubkey:%s\n", encoded)
		fmt.Fprintf(cliSide, "pubkeys-done\n")

		// Read sign request and respond.
		for {
			line, err := cliReader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)

			if !strings.HasPrefix(line, "sign:") {
				continue
			}

			// Parse sign:{base64 pubkey}:{base64 data}
			payload := line[5:]
			colonIdx := strings.Index(payload, ":")
			if colonIdx < 0 {
				fmt.Fprintf(cliSide, "sig-err:malformed\n")
				continue
			}

			dataB64 := payload[colonIdx+1:]
			data, err := base64.StdEncoding.DecodeString(dataB64)
			if err != nil {
				fmt.Fprintf(cliSide, "sig-err:bad data\n")
				continue
			}

			sig, err := signer.Sign(rand.Reader, data)
			if err != nil {
				fmt.Fprintf(cliSide, "sig-err:%v\n", err)
				continue
			}

			sigBytes := ssh.Marshal(sig)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
			fmt.Fprintf(cliSide, "sig:%s\n", sigB64)
		}
	}()

	// Read public keys.
	err = signCh.ReadPublicKeys()
	require.NoError(t, err)
	require.True(t, signCh.HasKeys())

	// Get signers and test signing.
	signers := signCh.Signers()
	require.Len(t, signers, 1)

	testData := []byte("test data to sign")
	sig, err := signers[0].Sign(nil, testData)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify the signature is valid.
	err = pubKey.Verify(testData, sig)
	require.NoError(t, err)
}

func TestProxy_HandlePreAuth(t *testing.T) {
	// Test HandlePreAuth with a pre-authenticated target SSH connection.
	logger := slog.Default()

	// Generate proxy host key.
	_, proxyPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	proxySigner, err := ssh.NewSignerFromKey(proxyPriv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(proxySigner, logger)

	// Generate a user key for pubkey auth.
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	require.NoError(t, err)

	// Create connection pairs.
	clientConn, proxyClientConn := connPair(t)
	proxyTargetConn, targetConn := connPair(t)

	// Start target SSH server that accepts the user's public key.
	go testSSHServerWithPubKey(t, targetConn, userSigner.PublicKey())

	// Pre-authenticate: bridge opens SSH to target using the user's key.
	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	targetSSH, targetChans, targetReqs, err := ssh.NewClientConn(proxyTargetConn, "target", clientConfig)
	require.NoError(t, err)

	// Run HandlePreAuth in background.
	var result *SessionResult
	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, proxyErr = proxy.HandlePreAuth(ctx, proxyClientConn, targetSSH, targetChans, targetReqs, "test-preauth-session-1234567890")
	}()

	// Connect as SSH client through the proxy (NoClientAuth).
	proxyClientConfig := &ssh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientSSH, clientChans, clientReqs, err := ssh.NewClientConn(clientConn, "proxy", proxyClientConfig)
	require.NoError(t, err)

	client := ssh.NewClient(clientSSH, clientChans, clientReqs)

	session, err := client.NewSession()
	require.NoError(t, err)

	err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	require.NoError(t, err)

	output, err := session.Output("hostname")
	require.NoError(t, err)
	require.Contains(t, string(output), "exec: hostname")

	session.Close()
	client.Close()

	wg.Wait()
	require.NoError(t, proxyErr)
	require.NotNil(t, result)
	require.Greater(t, len(result.Recording), 0)

	// Verify recording.
	recording := string(result.Recording)
	lines := strings.Split(strings.TrimSpace(recording), "\n")
	require.GreaterOrEqual(t, len(lines), 2)

	var header asciicastHeader
	err = json.Unmarshal([]byte(lines[0]), &header)
	require.NoError(t, err)
	require.Equal(t, 2, header.Version)
}

func TestProxy_PortForwardRejected(t *testing.T) {
	// Verify that direct-tcpip (port forwarding) channels are rejected
	// on audited sessions to prevent audit bypass.
	logger := slog.Default()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	proxy := NewProxyWithSigner(signer, logger)

	clientConn, proxyClientConn := connPair(t)
	proxyTargetConn, targetConn := connPair(t)

	go testSSHServer(t, targetConn)

	var proxyErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, proxyErr = proxy.Handle(ctx, proxyClientConn, proxyTargetConn, "test-portfwd-session-1234567890")
	}()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientSSH, clientChans, clientReqs, err := ssh.NewClientConn(clientConn, "proxy", clientConfig)
	require.NoError(t, err)

	client := ssh.NewClient(clientSSH, clientChans, clientReqs)

	// Try to open a direct-tcpip channel (port forwarding).
	_, _, err = client.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   "127.0.0.1",
		DestPort:   8080,
		OriginAddr: "127.0.0.1",
		OriginPort: 12345,
	}))

	// Port forwarding must be rejected.
	require.Error(t, err)
	var openErr *ssh.OpenChannelError
	require.ErrorAs(t, err, &openErr)
	require.Equal(t, ssh.Prohibited, openErr.Reason)

	client.Close()

	wg.Wait()
	require.NoError(t, proxyErr)
}
