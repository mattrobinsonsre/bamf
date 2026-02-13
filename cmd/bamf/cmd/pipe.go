package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var pipeCmd = &cobra.Command{
	Use:   "pipe <resource>",
	Short: "Pipe stdin/stdout through a tunnel to a resource",
	Long: `Connect to a resource through the BAMF bridge, splicing stdin/stdout
to the tunnel. This is the raw building block for protocol-specific commands.

Used as an SSH ProxyCommand:
  Host *.prod
    ProxyCommand bamf pipe %h

Or directly for any protocol where the client reads/writes stdio:
  bamf pipe prod-redis | redis-cli --pipe`,
	Args: cobra.ExactArgs(1),
	RunE: runPipe,
}

func init() {
	rootCmd.AddCommand(pipeCmd)
}

func runPipe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	resourceName := args[0]

	bridgeConn, _, err := connectBridge(ctx, resourceName)
	if err != nil {
		return err
	}
	defer bridgeConn.Close()

	// Splice stdin/stdout <-> bridge
	return splice(ctx, readWriteCloser{os.Stdin, os.Stdout}, bridgeConn)
}

// readWriteCloser combines separate reader and writer into io.ReadWriteCloser.
type readWriteCloser struct {
	r *os.File
	w *os.File
}

func (rw readWriteCloser) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw readWriteCloser) Write(p []byte) (int, error) { return rw.w.Write(p) }
func (rw readWriteCloser) Close() error                { return nil }
