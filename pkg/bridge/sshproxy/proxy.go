// Package sshproxy implements a bridge-side SSH-terminating proxy for session
// recording. When a tunnel has resource type "ssh-audit", the bridge routes
// the connection through this proxy instead of the standard byte-splice tunnel.
//
// Architecture:
//
//	Client SSH ──▶ Bridge SSHProxy ──▶ Agent ──▶ Target sshd
//	               (terminates SSH)    (byte pipe)
//	               (records stdout)
//
// The proxy terminates the client's SSH connection (acts as SSH server),
// captures terminal output in asciicast v2 format, then opens a new SSH
// connection to the target through the agent tunnel (acts as SSH client).
//
// Trade-off: ssh-audit sessions cannot survive bridge pod failure because
// SSH encryption state lives in the bridge process. Regular "ssh" type
// retains the reliable stream for bridge-death survival.
package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Proxy handles SSH-terminating proxy connections for session recording.
type Proxy struct {
	hostSigner ssh.Signer
	logger     *slog.Logger
}

// NewProxy creates a new SSH proxy with an ephemeral host key.
// Prefer NewProxyFromTLSKey for stable host keys across bridge restarts.
func NewProxy(logger *slog.Logger) (*Proxy, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Proxy{
		hostSigner: signer,
		logger:     logger,
	}, nil
}

// NewProxyFromTLSKey creates an SSH proxy using the bridge's TLS private key
// as the SSH host key. This ensures the host key is stable across bridge pod
// restarts (as long as the TLS cert is the same), preventing "REMOTE HOST
// IDENTIFICATION HAS CHANGED" warnings for users.
func NewProxyFromTLSKey(keyPEM []byte, logger *slog.Logger) (*Proxy, error) {
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS key as SSH signer: %w", err)
	}

	return &Proxy{
		hostSigner: signer,
		logger:     logger,
	}, nil
}

// NewProxyWithSigner creates a proxy with an explicit host signer (for testing).
func NewProxyWithSigner(signer ssh.Signer, logger *slog.Logger) *Proxy {
	return &Proxy{
		hostSigner: signer,
		logger:     logger,
	}
}

// SessionResult contains the recording data after a session completes.
type SessionResult struct {
	Recording []byte // asciicast v2 data
}

// Handle proxies an SSH session between clientConn and agentConn, recording
// terminal output. The agentConn is a raw TCP pipe to the target sshd
// (through the agent tunnel).
//
// The proxy:
// 1. Accepts the client SSH handshake (NoClientAuth — mTLS already authenticated)
// 2. Opens an SSH connection to the target through agentConn
// 3. For each client channel request, opens a matching channel on the target
// 4. Records stdout from the target in asciicast v2 format
// 5. Returns the recording when the session closes
func (p *Proxy) Handle(ctx context.Context, clientConn net.Conn, agentConn net.Conn, sessionID string, warnCh <-chan string) (*SessionResult, error) {
	logger := p.logger.With("session_id", sessionID[:min(16, len(sessionID))]+"...")

	// Capture client credentials during SSH auth. The bridge SSH proxy
	// accepts password and keyboard-interactive auth from the client,
	// then replays those credentials to the target sshd.
	var capturedUser string
	var capturedPassword string

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			capturedUser = conn.User()
			capturedPassword = string(password)
			// Always accept — real auth happens against the target.
			return nil, nil
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// For keyboard-interactive, issue a single password prompt
			// and capture the response.
			capturedUser = conn.User()
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) > 0 {
				capturedPassword = answers[0]
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(p.hostSigner)

	clientSSH, clientChans, clientReqs, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("client SSH handshake failed: %w", err)
	}
	defer clientSSH.Close()

	logger.Info("client SSH handshake complete",
		"client_version", string(clientSSH.ClientVersion()),
		"user", capturedUser,
	)

	// Open SSH connection to target through agent tunnel, replaying the
	// captured credentials. Try password auth (most common for SSH targets).
	clientConfig := &ssh.ClientConfig{
		User:            capturedUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Agent tunnel is mTLS-authenticated
		Auth: []ssh.AuthMethod{
			ssh.Password(capturedPassword),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				// Reply to all prompts with the captured password.
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = capturedPassword
				}
				return answers, nil
			}),
		},
	}

	targetSSH, targetChans, targetReqs, err := ssh.NewClientConn(agentConn, "target", clientConfig)
	if err != nil {
		return nil, fmt.Errorf("target SSH handshake failed: %w", err)
	}
	defer targetSSH.Close()

	logger.Info("target SSH handshake complete")

	// Discard global requests from both sides.
	go ssh.DiscardRequests(clientReqs)
	go ssh.DiscardRequests(targetReqs)

	// Reject channels opened by the target (reverse port forwards, etc.).
	go discardChannels(targetChans)

	recording := NewRecording()

	// Handle client channel requests (session, direct-tcpip, etc.).
	var wg sync.WaitGroup
	for newCh := range clientChans {
		chType := newCh.ChannelType()

		if chType != "session" {
			// Reject non-session channels (direct-tcpip, forwarded-tcpip).
			// Port forwarding would allow users to bypass session recording
			// by tunneling an unrecorded connection through the audited session.
			_ = newCh.Reject(ssh.Prohibited, "port forwarding is not permitted on audited sessions")
			logger.Warn("rejected channel type on audited session", "type", chType)
			continue
		}

		// Session channel: forward with recording.
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			if err := p.handleSessionChannel(targetSSH, nc, recording, logger, warnCh); err != nil {
				logger.Debug("session channel ended", "error", err)
			}
		}(newCh)
	}

	wg.Wait()
	logger.Info("SSH proxy session complete", "recording_bytes", recording.Len())

	return &SessionResult{
		Recording: recording.Bytes(),
	}, nil
}

// HandlePreAuth proxies an SSH session where the target connection is already
// authenticated. Used when remote signing pre-authenticates the bridge→target
// SSH connection during the pre-flight phase (before client SSH data flows).
//
// The proxy only handles the client SSH handshake (NoClientAuth — mTLS already
// authenticated the user) and channel forwarding with recording.
func (p *Proxy) HandlePreAuth(ctx context.Context, clientConn net.Conn, targetSSH ssh.Conn, targetChans <-chan ssh.NewChannel, targetReqs <-chan *ssh.Request, sessionID string, warnCh <-chan string) (*SessionResult, error) {
	logger := p.logger.With("session_id", sessionID[:min(16, len(sessionID))]+"...")

	// Accept client SSH with NoClientAuth — mTLS already authenticated,
	// and the bridge already authenticated to the target via remote signing.
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	serverConfig.AddHostKey(p.hostSigner)

	clientSSH, clientChans, clientReqs, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("client SSH handshake failed: %w", err)
	}
	defer clientSSH.Close()
	defer targetSSH.Close()

	logger.Info("client SSH handshake complete (pre-auth)",
		"client_version", string(clientSSH.ClientVersion()),
		"user", clientSSH.User(),
	)

	// Discard global requests from both sides.
	go ssh.DiscardRequests(clientReqs)
	go ssh.DiscardRequests(targetReqs)

	// Reject channels opened by the target (reverse port forwards, etc.).
	go discardChannels(targetChans)

	recording := NewRecording()

	var wg sync.WaitGroup
	for newCh := range clientChans {
		chType := newCh.ChannelType()

		if chType != "session" {
			_ = newCh.Reject(ssh.Prohibited, "port forwarding is not permitted on audited sessions")
			logger.Warn("rejected channel type on audited session", "type", chType)
			continue
		}

		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			if err := p.handleSessionChannel(targetSSH, nc, recording, logger, warnCh); err != nil {
				logger.Debug("session channel ended", "error", err)
			}
		}(newCh)
	}

	wg.Wait()
	logger.Info("SSH proxy session complete", "recording_bytes", recording.Len())

	return &SessionResult{
		Recording: recording.Bytes(),
	}, nil
}

// HandleDirect sets up an SSH session to the target and returns the channel
// as an io.ReadWriteCloser, plus a Recording for session capture. Unlike
// Handle/HandlePreAuth which manage the full bidirectional relay internally,
// HandleDirect returns the channel so the caller (webterm.Session) can manage
// the relay with reconnection support.
//
// When record is true, the returned io.ReadWriteCloser is a RecordingChannel
// that tees reads into the Recording. When false, no recording is created
// and the returned Recording is nil. This respects the resource's audit
// classification — only ssh-audit resources should be recorded.
//
// Used by web-ssh sessions where the bridge receives credentials from the
// browser (via the API) and authenticates directly to the target.
// authMethods should contain ssh.PublicKeys(signer) for key auth or
// ssh.Password(password) for password auth.
func (p *Proxy) HandleDirect(agentConn net.Conn, username string, authMethods []ssh.AuthMethod, cols, rows int, record bool, logger *slog.Logger) (io.ReadWriteCloser, *Recording, error) {
	clientConfig := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Agent tunnel is mTLS-authenticated
		Auth:            authMethods,
	}

	targetSSH, targetChans, targetReqs, err := ssh.NewClientConn(agentConn, "target", clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("target SSH auth failed: %w", err)
	}

	go ssh.DiscardRequests(targetReqs)
	go discardChannels(targetChans)

	// Open a session channel on the target.
	targetCh, targetReqCh, err := targetSSH.OpenChannel("session", nil)
	if err != nil {
		targetSSH.Close()
		return nil, nil, fmt.Errorf("failed to open session channel: %w", err)
	}
	go ssh.DiscardRequests(targetReqCh)

	var recording *Recording
	if record {
		recording = NewRecording()
	}

	// Request PTY.
	ptyReqPayload := ssh.Marshal(struct {
		Term     string
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
		Modes    string
	}{
		Term:   "xterm-256color",
		Width:  uint32(cols),
		Height: uint32(rows),
		Modes:  "",
	})
	ok, err := targetCh.SendRequest("pty-req", true, ptyReqPayload)
	if err != nil || !ok {
		targetCh.Close()
		targetSSH.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("pty-req failed: %w", err)
		}
		return nil, nil, fmt.Errorf("pty-req rejected")
	}

	if recording != nil {
		recording.Start(cols, rows, map[string]string{"TERM": "xterm-256color"})
	}

	// Request shell.
	ok, err = targetCh.SendRequest("shell", true, nil)
	if err != nil || !ok {
		targetCh.Close()
		targetSSH.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("shell request failed: %w", err)
		}
		return nil, nil, fmt.Errorf("shell request rejected")
	}

	logger.Info("SSH session established via HandleDirect",
		"user", username,
		"cols", cols,
		"rows", rows,
		"recording", record,
	)

	if recording != nil {
		// Wrap the SSH channel with a recording tee on reads (target→client).
		rw := &RecordingChannel{
			ch:        targetCh,
			recording: recording,
			targetSSH: targetSSH,
		}
		return rw, recording, nil
	}

	// No recording — return a plain channel wrapper.
	rw := &PlainChannel{
		ch:        targetCh,
		targetSSH: targetSSH,
	}
	return rw, nil, nil
}

// PlainChannel wraps an ssh.Channel without recording.
// Implements io.ReadWriteCloser. Used for non-audit web-ssh sessions.
type PlainChannel struct {
	ch        ssh.Channel
	targetSSH ssh.Conn
}

func (pc *PlainChannel) Read(p []byte) (int, error) {
	return pc.ch.Read(p)
}

func (pc *PlainChannel) Write(p []byte) (int, error) {
	return pc.ch.Write(p)
}

func (pc *PlainChannel) Close() error {
	pc.ch.Close()
	return pc.targetSSH.Close()
}

// SendWindowChange sends a window-change request on the SSH channel.
func (pc *PlainChannel) SendWindowChange(cols, rows uint16) {
	payload := ssh.Marshal(struct {
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
	}{
		Width:  uint32(cols),
		Height: uint32(rows),
	})
	_, _ = pc.ch.SendRequest("window-change", false, payload)
}

// RecordingChannel wraps an ssh.Channel to record stdout on Read and
// support window-change requests. Implements io.ReadWriteCloser.
type RecordingChannel struct {
	ch        ssh.Channel
	recording *Recording
	targetSSH ssh.Conn
}

func (rc *RecordingChannel) Read(p []byte) (int, error) {
	n, err := rc.ch.Read(p)
	if n > 0 {
		rc.recording.Output(p[:n])
	}
	return n, err
}

func (rc *RecordingChannel) Write(p []byte) (int, error) {
	return rc.ch.Write(p)
}

func (rc *RecordingChannel) Close() error {
	rc.ch.Close()
	return rc.targetSSH.Close()
}

// SendWindowChange sends a window-change request on the SSH channel.
func (rc *RecordingChannel) SendWindowChange(cols, rows uint16) {
	payload := ssh.Marshal(struct {
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
	}{
		Width:  uint32(cols),
		Height: uint32(rows),
	})
	_, _ = rc.ch.SendRequest("window-change", false, payload)
	rc.recording.Resize(int(cols), int(rows))
}

// handleSessionChannel handles an SSH "session" channel with recording.
// If warnCh is non-nil, a goroutine monitors it and writes drain warnings
// to the client's stderr (visible in the user's terminal).
func (p *Proxy) handleSessionChannel(
	targetConn ssh.Conn,
	clientNewCh ssh.NewChannel,
	rec *Recording,
	logger *slog.Logger,
	warnCh <-chan string,
) error {
	// Accept client channel.
	clientCh, clientReqs, err := clientNewCh.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept client channel: %w", err)
	}
	defer clientCh.Close()

	// Monitor drain warning channel — write messages to the client's stderr
	// so the user sees warnings in their terminal during bridge shutdown.
	warnDone := make(chan struct{})
	go func() {
		defer close(warnDone)
		if warnCh == nil {
			return
		}
		for msg := range warnCh {
			if _, err := clientCh.Stderr().Write([]byte(msg)); err != nil {
				logger.Debug("failed to write drain warning to stderr", "error", err)
				return
			}
		}
	}()

	// Open matching channel on target.
	targetCh, targetReqs, err := targetConn.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("failed to open target session channel: %w", err)
	}
	defer targetCh.Close()

	// Forward channel requests bidirectionally, intercepting pty-req
	// and window-change for recording metadata.

	// target → client requests (exit-status, exit-signal).
	// This goroutine must finish before we close clientCh, so exit-status
	// is forwarded to the client (needed for session.Wait()).
	targetReqsDone := make(chan struct{})
	go func() {
		defer close(targetReqsDone)
		for req := range targetReqs {
			ok, err := clientCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				if err != nil {
					_ = req.Reply(false, nil)
				} else {
					_ = req.Reply(ok, nil)
				}
			}
		}
	}()

	// client → target requests (pty-req, shell, exec, env, window-change, subsystem)
	go func() {
		for req := range clientReqs {
			switch req.Type {
			case "pty-req":
				pty, err := parsePtyReq(req.Payload)
				if err == nil {
					rec.Start(int(pty.Width), int(pty.Height), map[string]string{
						"TERM": pty.Term,
					})
					logger.Debug("pty-req", "term", pty.Term, "width", pty.Width, "height", pty.Height)
				}
			case "shell", "exec":
				// Ensure recording is started even without a PTY.
				// Without this, `ssh user@host "command"` would bypass
				// recording entirely since no pty-req is sent.
				rec.EnsureStarted()
			case "window-change":
				wc, err := parseWindowChange(req.Payload)
				if err == nil {
					rec.Resize(int(wc.Width), int(wc.Height))
				}
			}

			ok, err := targetCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				if err != nil {
					_ = req.Reply(false, nil)
				} else {
					_ = req.Reply(ok, nil)
				}
			}
		}
	}()

	// Bidirectional data copy with recording on the target→client direction.
	// Use done channels to coordinate close propagation in both directions.
	targetToClientDone := make(chan struct{})
	clientToTargetDone := make(chan struct{})

	go func() {
		defer close(targetToClientDone)
		// target stdout → client (with recording)
		recW := newRecordingWriter(clientCh, rec)
		io.Copy(recW, targetCh) //nolint:errcheck
	}()

	go func() {
		defer close(clientToTargetDone)
		// client stdin → target (no recording — avoids capturing passwords)
		io.Copy(targetCh, clientCh) //nolint:errcheck
		// Client closed stdin — signal target that no more input is coming.
		// This unblocks the target's read loop (e.g., shell echo mode).
		_ = targetCh.CloseWrite()
	}()

	go func() {
		// target stderr → client stderr (with recording)
		recW := newRecordingWriter(clientCh.Stderr(), rec)
		io.Copy(recW, targetCh.Stderr()) //nolint:errcheck
	}()

	// Wait for either direction to finish, then ensure orderly shutdown.
	// Two scenarios:
	// 1. Target closes first (exec, exit): wait for exit-status, then close client
	// 2. Client closes first (disconnect): propagate via CloseWrite, wait for target
	select {
	case <-targetToClientDone:
		// Target stdout closed — exec complete or shell exit.
		// Wait for exit-status/exit-signal to be forwarded to client.
		<-targetReqsDone
	case <-clientToTargetDone:
		// Client disconnected — target will see EOF and close.
		<-targetToClientDone
		<-targetReqsDone
	}

	// Close both channels to terminate remaining goroutines.
	targetCh.Close()
	clientCh.Close()

	return nil
}

// discardChannels rejects all incoming channel requests.
func discardChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		_ = ch.Reject(ssh.Prohibited, "server-initiated channels not supported")
	}
}

// ptyReq holds parsed pty-req payload.
type ptyReq struct {
	Term   string
	Width  uint32
	Height uint32
}

// parsePtyReq parses an SSH pty-req payload.
// Wire format: string(term) + uint32(width) + uint32(height) + uint32(pxWidth) + uint32(pxHeight) + string(modes)
func parsePtyReq(payload []byte) (ptyReq, error) {
	var req struct {
		Term     string
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
		Modes    string
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return ptyReq{}, err
	}
	return ptyReq{
		Term:   req.Term,
		Width:  req.Width,
		Height: req.Height,
	}, nil
}

// windowChange holds parsed window-change payload.
type windowChange struct {
	Width  uint32
	Height uint32
}

// parseWindowChange parses an SSH window-change payload.
func parseWindowChange(payload []byte) (windowChange, error) {
	var req struct {
		Width    uint32
		Height   uint32
		PxWidth  uint32
		PxHeight uint32
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return windowChange{}, err
	}
	return windowChange{
		Width:  req.Width,
		Height: req.Height,
	}, nil
}
