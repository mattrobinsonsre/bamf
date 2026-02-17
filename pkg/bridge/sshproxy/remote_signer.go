package sshproxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// remoteSigner implements ssh.Signer by sending sign requests to the CLI
// over a text protocol. The CLI signs using the local SSH agent and sends
// back the signature. This enables key-based auth for ssh-audit sessions
// without the bridge ever seeing the user's private key.
type remoteSigner struct {
	pubKey   ssh.PublicKey
	signFunc func(pubKey ssh.PublicKey, data []byte) (*ssh.Signature, error)
}

func (rs *remoteSigner) PublicKey() ssh.PublicKey {
	return rs.pubKey
}

func (rs *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return rs.signFunc(rs.pubKey, data)
}

// SignChannel handles the pre-flight signing protocol between the bridge and
// CLI. It reads public keys from the CLI, then provides a signFunc that sends
// sign requests and reads responses. Thread-safe: the signFunc serializes
// requests since the text protocol is line-oriented.
type SignChannel struct {
	reader *bufio.Reader
	writer io.Writer
	mu     sync.Mutex // Serializes sign requests on the text channel.
	logger *slog.Logger
	keys   []ssh.PublicKey
}

// NewSignChannel creates a sign channel from a buffered reader and writer
// (typically the client connection). Call ReadPublicKeys() first, then use
// Signers() to get SSH signers for the target connection.
func NewSignChannel(reader *bufio.Reader, writer io.Writer, logger *slog.Logger) *SignChannel {
	return &SignChannel{
		reader: reader,
		writer: writer,
		logger: logger,
	}
}

// ReadPublicKeys reads pubkey lines from the CLI until "pubkeys-done".
// Format: "pubkey:{base64-wire-format-public-key}\n" per key.
func (sc *SignChannel) ReadPublicKeys() error {
	for {
		line, err := sc.reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read pubkey line: %w", err)
		}
		line = strings.TrimSpace(line)

		if line == "pubkeys-done" {
			sc.logger.Debug("received public keys from CLI", "count", len(sc.keys))
			return nil
		}

		keyB64, ok := strings.CutPrefix(line, "pubkey:")
		if !ok {
			return fmt.Errorf("unexpected line during pubkey exchange: %q", line)
		}

		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			sc.logger.Warn("skipping malformed public key", "error", err)
			continue
		}

		pubKey, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
			sc.logger.Warn("skipping unparseable public key", "error", err)
			continue
		}

		sc.keys = append(sc.keys, pubKey)
	}
}

// HasKeys returns true if the CLI sent at least one public key.
func (sc *SignChannel) HasKeys() bool {
	return len(sc.keys) > 0
}

// Signers returns SSH signers backed by the remote CLI's SSH agent.
// Each signer sends a sign request over the text channel when Sign() is called.
func (sc *SignChannel) Signers() []ssh.Signer {
	signers := make([]ssh.Signer, len(sc.keys))
	for i, key := range sc.keys {
		signers[i] = &remoteSigner{
			pubKey:   key,
			signFunc: sc.sign,
		}
	}
	return signers
}

// sign sends a sign request to the CLI and reads the response.
// Thread-safe: serializes requests with a mutex since the text protocol
// is line-oriented and can't multiplex.
func (sc *SignChannel) sign(pubKey ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	keyB64 := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	dataB64 := base64.StdEncoding.EncodeToString(data)

	// Send sign request.
	req := fmt.Sprintf("sign:%s:%s\n", keyB64, dataB64)
	if _, err := sc.writer.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("failed to send sign request: %w", err)
	}

	// Read response.
	line, err := sc.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read sign response: %w", err)
	}
	line = strings.TrimSpace(line)

	if errMsg, ok := strings.CutPrefix(line, "sig-err:"); ok {
		return nil, fmt.Errorf("remote signing failed: %s", errMsg)
	}

	sigB64, ok := strings.CutPrefix(line, "sig:")
	if !ok {
		return nil, fmt.Errorf("unexpected sign response: %q", line)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Parse the SSH signature wire format.
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	return &sig, nil
}

// SendReady tells the CLI that the pre-flight phase is complete and SSH
// data can start flowing.
func (sc *SignChannel) SendReady() error {
	_, err := sc.writer.Write([]byte("ready\n"))
	return err
}
