package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/mattrobinsonsre/bamf/pkg/tunnel"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var pipeCmd = &cobra.Command{
	Use:   "pipe <resource> [username]",
	Short: "Pipe stdin/stdout through a tunnel to a resource",
	Long: `Connect to a resource through the BAMF bridge, splicing stdin/stdout
to the tunnel. This is the raw building block for protocol-specific commands.

Used as an SSH ProxyCommand:
  Host *.prod
    ProxyCommand bamf pipe %h %r

Or directly for any protocol where the client reads/writes stdio:
  bamf pipe prod-redis | redis-cli --pipe`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runPipe,
}

func init() {
	rootCmd.AddCommand(pipeCmd)
}

func runPipe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	notifySignals(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	resourceName := args[0]
	sshUser := ""
	if len(args) > 1 {
		sshUser = args[1]
	}

	// Check resource type to determine connection mode. For ssh-audit, the
	// bridge terminates SSH directly, so we need a raw connection (no reliable
	// stream framing). For all other types, use the reliable stream.
	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w\nRun 'bamf login' to authenticate", err)
	}

	session, err := requestConnect(ctx, creds, resourceName, "")
	if err != nil {
		return fmt.Errorf("failed to request session: %w", err)
	}

	if session.ResourceType == "ssh-audit" {
		// Raw connection — bridge SSH proxy terminates SSH directly.
		conn, err := dialBridge(ctx, session)
		if err != nil {
			return fmt.Errorf("failed to connect to bridge: %w", err)
		}
		defer conn.Close()

		// Pre-flight signing protocol: send public keys from the local
		// SSH agent so the bridge can authenticate to the target with
		// key-based auth. If no agent is available, send zero keys and
		// the bridge falls back to password capture/replay.
		if err := sshAuditPreflight(conn, sshUser); err != nil {
			return fmt.Errorf("ssh-audit pre-flight failed: %w", err)
		}

		return splice(ctx, readWriteCloser{os.Stdin, os.Stdout}, conn)
	}

	// Standard reliable stream connection.
	conn, err := dialBridge(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to connect to bridge: %w", err)
	}

	stream := tunnel.NewStream(conn, tunnel.DefaultBufSize)
	rb := &reconnectingBridge{
		stream:       stream,
		session:      session,
		creds:        creds,
		resourceName: resourceName,
		ctx:          ctx,
	}
	defer rb.Close()

	// Splice stdin/stdout <-> bridge
	return splice(ctx, readWriteCloser{os.Stdin, os.Stdout}, rb)
}

// sshAuditPreflight runs the pre-flight signing protocol for ssh-audit
// sessions. It sends public keys from the local SSH agent to the bridge,
// handles sign requests so the bridge can do key-based auth to the target,
// then waits for the bridge to signal "ready" before returning.
//
// If no SSH agent is available or it has no keys, this sends zero keys
// and the bridge falls back to password capture/replay.
func sshAuditPreflight(conn net.Conn, sshUser string) error {
	// Try to connect to the local SSH agent.
	var ag sshagent.ExtendedAgent
	var agentKeys []*sshagent.Key
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		agentConn, err := net.Dial("unix", sock)
		if err == nil {
			defer agentConn.Close()
			ag = sshagent.NewClient(agentConn)
			keys, err := ag.List()
			if err == nil {
				agentKeys = keys
			}
		}
	}

	// Send public keys.
	for _, key := range agentKeys {
		encoded := base64.StdEncoding.EncodeToString(key.Marshal())
		if _, err := fmt.Fprintf(conn, "pubkey:%s\n", encoded); err != nil {
			return fmt.Errorf("failed to send public key: %w", err)
		}
	}
	if _, err := fmt.Fprintf(conn, "pubkeys-done\n"); err != nil {
		return fmt.Errorf("failed to send pubkeys-done: %w", err)
	}

	// If we sent keys, also send the SSH username so the bridge can
	// authenticate to the target before the client SSH handshake.
	if len(agentKeys) > 0 {
		if _, err := fmt.Fprintf(conn, "user=%s\n", sshUser); err != nil {
			return fmt.Errorf("failed to send username: %w", err)
		}
	}

	// Handle sign requests until "ready".
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read pre-flight response: %w", err)
		}
		line = strings.TrimSpace(line)

		if line == "ready" {
			// Pre-flight complete. The bufio.Reader may have buffered
			// data beyond "ready\n" (the start of SSH protocol bytes).
			// Push any buffered data back by replacing conn's read path.
			// Since splice uses the conn directly, we need to drain the
			// reader's buffer first.
			if reader.Buffered() > 0 {
				// There shouldn't be buffered data here since "ready" is
				// the last thing the bridge sends before SSH starts, and
				// the native ssh client hasn't sent anything yet. But
				// handle it defensively.
				buf := make([]byte, reader.Buffered())
				if _, err := reader.Read(buf); err != nil {
					return fmt.Errorf("read buffered data: %w", err)
				}
				if _, err := os.Stdout.Write(buf); err != nil {
					return fmt.Errorf("write buffered data: %w", err)
				}
			}
			return nil
		}

		if strings.HasPrefix(line, "sign:") {
			if ag == nil {
				fmt.Fprintf(conn, "sig-err:no SSH agent available\n")
				continue
			}

			// Parse: sign:{base64 pubkey}:{base64 data}
			payload := line[5:]
			colonIdx := strings.Index(payload, ":")
			if colonIdx < 0 {
				fmt.Fprintf(conn, "sig-err:malformed sign request\n")
				continue
			}

			keyB64 := payload[:colonIdx]
			dataB64 := payload[colonIdx+1:]

			keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
			if err != nil {
				fmt.Fprintf(conn, "sig-err:bad key encoding: %v\n", err)
				continue
			}

			data, err := base64.StdEncoding.DecodeString(dataB64)
			if err != nil {
				fmt.Fprintf(conn, "sig-err:bad data encoding: %v\n", err)
				continue
			}

			pubKey, err := ssh.ParsePublicKey(keyBytes)
			if err != nil {
				fmt.Fprintf(conn, "sig-err:bad public key: %v\n", err)
				continue
			}

			sig, err := ag.Sign(pubKey, data)
			if err != nil {
				fmt.Fprintf(conn, "sig-err:%v\n", err)
				continue
			}

			sigBytes := ssh.Marshal(sig)
			sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
			if _, err := fmt.Fprintf(conn, "sig:%s\n", sigB64); err != nil {
				return fmt.Errorf("failed to send signature: %w", err)
			}
			continue
		}

		// Unknown line — log and continue.
		fmt.Fprintf(os.Stderr, "bamf: unexpected pre-flight line: %s\n", line)
	}
}

// readWriteCloser combines separate reader and writer into io.ReadWriteCloser.
type readWriteCloser struct {
	r *os.File
	w *os.File
}

func (rw readWriteCloser) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw readWriteCloser) Write(p []byte) (int, error) { return rw.w.Write(p) }
func (rw readWriteCloser) Close() error                { return nil }
