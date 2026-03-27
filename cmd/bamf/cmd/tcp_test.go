package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandExecTemplate_AllVars(t *testing.T) {
	// Set globals used by expandExecTemplate
	oldUser, oldPass, oldDB := tcpUser, tcpPassword, tcpDBName
	tcpUser = "admin"
	tcpPassword = "secret"
	tcpDBName = "mydb"
	defer func() {
		tcpUser = oldUser
		tcpPassword = oldPass
		tcpDBName = oldDB
	}()

	result := expandExecTemplate("psql -h {host} -p {port} -U {user} -d {dbname}", "127.0.0.1", "5432")
	require.Equal(t, "psql -h 127.0.0.1 -p 5432 -U admin -d mydb", result)
}

func TestExpandExecTemplate_Password(t *testing.T) {
	oldPass := tcpPassword
	tcpPassword = "s3cr3t"
	defer func() { tcpPassword = oldPass }()

	result := expandExecTemplate("redis-cli -h {host} -p {port} -a {password}", "localhost", "6379")
	require.Equal(t, "redis-cli -h localhost -p 6379 -a s3cr3t", result)
}

func TestExpandExecTemplate_NoVars(t *testing.T) {
	result := expandExecTemplate("echo hello", "127.0.0.1", "8080")
	require.Equal(t, "echo hello", result)
}

func TestExpandExecTemplate_PartialVars(t *testing.T) {
	oldUser := tcpUser
	tcpUser = "root"
	defer func() { tcpUser = oldUser }()

	result := expandExecTemplate("mysql -h {host} -P {port} -u {user}", "127.0.0.1", "3306")
	require.Equal(t, "mysql -h 127.0.0.1 -P 3306 -u root", result)
}

func TestExpandExecTemplate_EmptyVars(t *testing.T) {
	oldUser, oldPass, oldDB := tcpUser, tcpPassword, tcpDBName
	tcpUser = ""
	tcpPassword = ""
	tcpDBName = ""
	defer func() {
		tcpUser = oldUser
		tcpPassword = oldPass
		tcpDBName = oldDB
	}()

	result := expandExecTemplate("cmd -u {user} -p {password} -d {dbname}", "host", "1234")
	require.Equal(t, "cmd -u  -p  -d ", result)
}
