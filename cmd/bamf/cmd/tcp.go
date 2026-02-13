package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	tcpLocalPort int
	tcpExecCmd   string
	tcpUser      string
	tcpPassword  string
	tcpDBName    string
)

var tcpCmd = &cobra.Command{
	Use:   "tcp <resource> [flags]",
	Short: "Open a TCP tunnel to a resource",
	Long: `Open a local TCP tunnel to a resource through BAMF.

Opens a local listener and forwards connections through the bridge to
the target resource. Any TCP protocol works — databases, Redis, SMTP,
custom services. The bridge is protocol-agnostic.

Without --exec, the tunnel stays open and prints the local address.
Connect your own client in another terminal.

With --exec, the specified command is run with template variables
substituted, and the tunnel closes when the command exits.

Template variables for --exec:
  {host}     — local listener address (127.0.0.1)
  {port}     — local listener port
  {user}     — from -U/--user flag
  {password} — from --password flag or BAMF_TCP_PASSWORD env
  {dbname}   — from -d/--dbname flag

Examples:
  # Open tunnel, connect manually
  bamf tcp prod-redis
  # => Listening on 127.0.0.1:54321

  # Open tunnel on specific port
  bamf tcp prod-redis -p 6380

  # Open tunnel and exec a command
  bamf tcp prod-redis --exec "redis-cli -h {host} -p {port}"

  # Template with user/password
  bamf tcp prod-mongo --exec "mongosh mongodb://{user}:{password}@{host}:{port}/{dbname}" -U admin -d mydb`,
	Args: cobra.MinimumNArgs(1),
	RunE: runTCP,
}

func init() {
	rootCmd.AddCommand(tcpCmd)
	tcpCmd.Flags().IntVarP(&tcpLocalPort, "port", "p", 0, "local port to listen on (0 = auto)")
	tcpCmd.Flags().StringVar(&tcpExecCmd, "exec", "", "command to exec with {host}, {port}, {user}, {password}, {dbname} templates")
	tcpCmd.Flags().StringVarP(&tcpUser, "user", "U", "", "username (available as {user} in --exec template)")
	tcpCmd.Flags().StringVar(&tcpPassword, "password", "", "password (available as {password} in --exec template)")
	tcpCmd.Flags().StringVarP(&tcpDBName, "dbname", "d", "", "database name (available as {dbname} in --exec template)")
}

func runTCP(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	resourceName := args[0]

	if tcpPassword == "" {
		tcpPassword = os.Getenv("BAMF_TCP_PASSWORD")
	}

	// Connect to bridge immediately (session cert has 30s TTL)
	bridgeConn, session, err := connectBridge(ctx, resourceName)
	if err != nil {
		return err
	}
	defer bridgeConn.Close()

	// Open local listener
	listenAddr := fmt.Sprintf("127.0.0.1:%d", tcpLocalPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)
	host := "127.0.0.1"
	port := strconv.Itoa(localAddr.Port)

	if tcpExecCmd != "" {
		fmt.Fprintf(os.Stderr, "Tunnel to %s ready on %s:%s\n", resourceName, host, port)
		return runTCPWithExec(ctx, listener, bridgeConn, host, port, args[1:])
	}

	fmt.Fprintf(os.Stderr, "Listening on %s:%s — tunnel to %s via %s\n",
		host, port, resourceName, session.BridgeHostname)
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to close the tunnel.\n")

	return serveTCPTunnel(ctx, listener, bridgeConn)
}

// expandExecTemplate substitutes template variables in the exec command string.
func expandExecTemplate(tmpl, host, port string) string {
	r := strings.NewReplacer(
		"{host}", host,
		"{port}", port,
		"{user}", tcpUser,
		"{password}", tcpPassword,
		"{dbname}", tcpDBName,
	)
	return r.Replace(tmpl)
}

// runTCPWithExec starts the exec'd command, accepts the first local connection,
// and splices it through the already-established bridge connection.
func runTCPWithExec(ctx context.Context, listener net.Listener, bridgeConn io.ReadWriteCloser, host, port string, extraArgs []string) error {
	expanded := expandExecTemplate(tcpExecCmd, host, port)
	cmdArgs := strings.Fields(expanded)
	cmdArgs = append(cmdArgs, extraArgs...)

	execCmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Accept first connection and splice it through the bridge
	go func() {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			}
			return
		}
		defer localConn.Close()
		if err := splice(ctx, localConn, bridgeConn); err != nil {
			fmt.Fprintf(os.Stderr, "tunnel error: %v\n", err)
		}
	}()

	if err := execCmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// serveTCPTunnel accepts the first local connection and splices it through
// the already-established bridge connection. One tunnel = one connection.
func serveTCPTunnel(ctx context.Context, listener net.Listener, bridgeConn io.ReadWriteCloser) error {
	localConn, err := listener.Accept()
	if err != nil {
		select {
		case <-ctx.Done():
			return nil
		default:
			return fmt.Errorf("accept error: %w", err)
		}
	}
	defer localConn.Close()

	return splice(ctx, localConn, bridgeConn)
}
