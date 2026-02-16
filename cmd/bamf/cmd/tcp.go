package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	tcpLocalPort  int
	tcpExecCmd    string
	tcpUser       string
	tcpPassword   string
	tcpDBName     string
	tcpBackground bool
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

  # Open tunnel in background (returns after connection is verified)
  bamf tcp prod-redis -p 6380 -b
  # => Listening on 127.0.0.1:6380 (PID 12345)

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
	tcpCmd.Flags().BoolVarP(&tcpBackground, "background", "b", false, "run tunnel in background (exits after connection is verified)")
}

// daemonReadyEnv is set on the re-exec'd child to indicate it should signal
// readiness via the pipe in ExtraFiles[0] (fd 3) instead of printing to stderr.
const daemonReadyEnv = "_BAMF_DAEMON"

func runTCP(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	notifySignals(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	resourceName := args[0]

	if tcpPassword == "" {
		tcpPassword = os.Getenv("BAMF_TCP_PASSWORD")
	}

	// Background mode: re-exec immediately as a detached child, then monitor
	// its readiness via a pipe. The child does all the real work.
	if tcpBackground && os.Getenv(daemonReadyEnv) == "" {
		return launchAndMonitor(args)
	}

	// Daemon child (or foreground): ignore SIGHUP if we're the daemon.
	isDaemon := os.Getenv(daemonReadyEnv) != ""
	if isDaemon {
		ignoreSIGHUP()
	}

	// Connect to bridge immediately (session cert has 30s TTL)
	bridgeConn, session, err := connectBridge(ctx, resourceName)
	if err != nil {
		signalDaemonResult(isDaemon, err, "")
		return err
	}
	defer bridgeConn.Close()

	// Open local listener
	listenAddr := fmt.Sprintf("127.0.0.1:%d", tcpLocalPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		err = fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
		signalDaemonResult(isDaemon, err, "")
		return err
	}
	defer listener.Close()

	localAddr := listener.Addr().(*net.TCPAddr)
	host := "127.0.0.1"
	port := strconv.Itoa(localAddr.Port)

	if tcpExecCmd != "" {
		fmt.Fprintf(os.Stderr, "Tunnel to %s ready on %s:%s\n", resourceName, host, port)
		signalDaemonResult(isDaemon, nil, port)
		return runTCPWithExec(ctx, listener, bridgeConn, host, port, args[1:])
	}

	// Signal readiness to parent (daemon mode) or print to stderr (foreground).
	if isDaemon {
		signalDaemonResult(isDaemon, nil, port)
	} else {
		fmt.Fprintf(os.Stderr, "Listening on %s:%s — tunnel to %s via %s\n",
			host, port, resourceName, session.BridgeHostname)
		fmt.Fprintf(os.Stderr, "Press Ctrl-C to close the tunnel.\n")
	}

	return serveTCPTunnel(ctx, listener, bridgeConn)
}

// launchAndMonitor re-execs the current binary as a detached child with a
// pipe for readiness signaling. The child does all the real work (auth, dial,
// listen). The parent blocks until the child signals ready or reports an error.
func launchAndMonitor(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find executable: %w", err)
	}

	// Rebuild args without -b/--background
	var childArgs []string
	for _, a := range os.Args[1:] {
		if a == "-b" || a == "--background" {
			continue
		}
		childArgs = append(childArgs, a)
	}

	// Pipe: child writes readiness or error to fd 3, parent reads.
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	defer pr.Close()

	child := exec.Command(exe, childArgs...)
	child.Env = append(os.Environ(), daemonReadyEnv+"=1")
	child.SysProcAttr = detachSysProcAttr()
	child.ExtraFiles = []*os.File{pw} // fd 3 in child

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer devNull.Close()
	child.Stdin = devNull
	child.Stdout = devNull
	child.Stderr = devNull

	if err := child.Start(); err != nil {
		return fmt.Errorf("failed to start background tunnel: %w", err)
	}
	pw.Close() // Parent closes write end; reads from pr.

	// Read the readiness message from the child.
	// Protocol: "OK <port>\n" on success, "ERR <message>\n" on failure.
	buf := make([]byte, 4096)
	n, readErr := pr.Read(buf)
	msg := ""
	if n > 0 {
		msg = strings.TrimSpace(string(buf[:n]))
	}

	if strings.HasPrefix(msg, "OK ") {
		port := strings.TrimPrefix(msg, "OK ")
		fmt.Fprintf(os.Stderr, "Listening on 127.0.0.1:%s (PID %d)\n", port, child.Process.Pid)
		_ = child.Process.Release()
		return nil
	}

	// Child failed or pipe broke before readiness.
	if strings.HasPrefix(msg, "ERR ") {
		_ = child.Process.Release()
		return fmt.Errorf("%s", strings.TrimPrefix(msg, "ERR "))
	}

	// Pipe closed without a message — child probably crashed.
	_ = child.Wait()
	if readErr != nil {
		return fmt.Errorf("background tunnel failed (pipe error: %w)", readErr)
	}
	return fmt.Errorf("background tunnel exited before becoming ready")
}

// signalDaemonResult writes a readiness or error message to the pipe (fd 3)
// that the parent is monitoring. No-op if not running as a daemon child.
// The port parameter is the actual bound port (important when tcpLocalPort is 0).
func signalDaemonResult(isDaemon bool, result error, port string) {
	if !isDaemon {
		return
	}
	// fd 3 = ExtraFiles[0] from the parent
	pipe := os.NewFile(3, "daemon-pipe")
	if pipe == nil {
		return
	}
	defer pipe.Close()
	if result != nil {
		fmt.Fprintf(pipe, "ERR %s\n", result)
	} else {
		fmt.Fprintf(pipe, "OK %s\n", port)
	}
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
	// Create a child context so we can cancel everything when the exec'd
	// command exits, ensuring the splice goroutine and listener clean up.
	execCtx, execCancel := context.WithCancel(ctx)
	defer execCancel()

	expanded := expandExecTemplate(tcpExecCmd, host, port)
	cmdArgs := strings.Fields(expanded)
	cmdArgs = append(cmdArgs, extraArgs...)

	execCmd := exec.CommandContext(execCtx, cmdArgs[0], cmdArgs[1:]...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	// Put child in its own process group so we can kill the whole group.
	execCmd.SysProcAttr = execGroupSysProcAttr()
	execCmd.Cancel = func() error {
		// Kill the entire process group on context cancellation.
		killProcessGroup(execCmd)
		return execCmd.Process.Kill()
	}

	// Close listener when exec context ends to unblock Accept.
	go func() {
		<-execCtx.Done()
		listener.Close()
	}()

	// Accept first connection and splice it through the bridge
	go func() {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-execCtx.Done():
			default:
				fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			}
			return
		}
		defer localConn.Close()
		if err := splice(execCtx, localConn, bridgeConn); err != nil {
			fmt.Fprintf(os.Stderr, "tunnel error: %v\n", err)
		}
	}()

	if err := execCmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		// Ignore the expected "signal: killed" from context cancellation.
		if execCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// serveTCPTunnel accepts the first local connection and splices it through
// the already-established bridge connection. One tunnel = one connection.
func serveTCPTunnel(ctx context.Context, listener net.Listener, bridgeConn io.ReadWriteCloser) error {
	// Close listener when context is cancelled to unblock Accept.
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

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
