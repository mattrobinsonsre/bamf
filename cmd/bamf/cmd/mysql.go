package cmd

import (
	"github.com/spf13/cobra"
)

var (
	mysqlUser   string
	mysqlDBName string
)

var mysqlCmd = &cobra.Command{
	Use:   "mysql <resource> [flags] [-- mysql args...]",
	Short: "Connect to a MySQL database via BAMF",
	Long: `Connect to a MySQL database through BAMF using mysql client.

Opens a TCP tunnel to the resource and execs mysql pointed at the local
listener. All flags before -- are handled by BAMF; everything after --
is passed through to mysql.

Examples:
  bamf mysql prod-mysql
  bamf mysql prod-mysql -u admin -D mydb
  bamf mysql prod-mysql -u admin -- -e "SHOW DATABASES;"`,
	Args: cobra.MinimumNArgs(1),
	RunE: runMySQL,
}

func init() {
	rootCmd.AddCommand(mysqlCmd)
	mysqlCmd.Flags().StringVarP(&mysqlUser, "user", "u", "", "database username")
	mysqlCmd.Flags().StringVarP(&mysqlDBName, "dbname", "D", "", "database name")
}

func runMySQL(cmd *cobra.Command, args []string) error {
	// Set the shared tcp flags from our local flags
	tcpUser = mysqlUser
	tcpDBName = mysqlDBName
	tcpLocalPort = 0 // auto-assign

	// Build the exec template — mysql uses -P for port (not -p which is password)
	tmpl := "mysql -h {host} -P {port}"
	if mysqlUser != "" {
		tmpl += " -u {user}"
	}
	if mysqlDBName != "" {
		tmpl += " -D {dbname}"
	}
	tcpExecCmd = tmpl

	return runTCP(cmd, args)
}
