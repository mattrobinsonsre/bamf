package cmd

import (
	"github.com/spf13/cobra"
)

var (
	psqlUser   string
	psqlDBName string
)

var psqlCmd = &cobra.Command{
	Use:   "psql <resource> [flags] [-- psql args...]",
	Short: "Connect to a PostgreSQL database via BAMF",
	Long: `Connect to a PostgreSQL database through BAMF using psql.

Opens a TCP tunnel to the resource and execs psql pointed at the local
listener. All flags before -- are handled by BAMF; everything after --
is passed through to psql.

Examples:
  bamf psql prod-postgres
  bamf psql prod-postgres -U admin -d mydb
  bamf psql prod-postgres -U admin -- -c "SELECT version();"
  bamf psql prod-postgres -- -f schema.sql`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPsql,
}

func init() {
	rootCmd.AddCommand(psqlCmd)
	psqlCmd.Flags().StringVarP(&psqlUser, "user", "U", "", "database username")
	psqlCmd.Flags().StringVarP(&psqlDBName, "dbname", "d", "", "database name")
}

func runPsql(cmd *cobra.Command, args []string) error {
	// Set the shared tcp flags from our local flags
	tcpUser = psqlUser
	tcpDBName = psqlDBName
	tcpLocalPort = 0 // auto-assign

	// Build the exec template
	tmpl := "psql -h {host} -p {port}"
	if psqlUser != "" {
		tmpl += " -U {user}"
	}
	if psqlDBName != "" {
		tmpl += " -d {dbname}"
	}
	tcpExecCmd = tmpl

	// Delegate to runTCP — extra args (after --) are passed through
	return runTCP(cmd, args)
}
