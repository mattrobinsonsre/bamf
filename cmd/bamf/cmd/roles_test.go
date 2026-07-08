package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJoinOrDash(t *testing.T) {
	require.Equal(t, "-", joinOrDash(nil))
	require.Equal(t, "-", joinOrDash([]string{}))
	require.Equal(t, "a", joinOrDash([]string{"a"}))
	require.Equal(t, "a,b", joinOrDash([]string{"a", "b"}))
}

func TestReadRoleFile(t *testing.T) {
	dir := t.TempDir()

	// YAML input
	yamlPath := filepath.Join(dir, "role.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte("name: dev\nallow:\n  labels:\n    env: [dev]\n"), 0600))
	body, err := readRoleFile(yamlPath)
	require.NoError(t, err)
	require.Equal(t, "dev", body["name"])

	// JSON input (JSON is valid YAML)
	jsonPath := filepath.Join(dir, "role.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"name":"ops","kubernetes_groups":["view"]}`), 0600))
	body, err = readRoleFile(jsonPath)
	require.NoError(t, err)
	require.Equal(t, "ops", body["name"])

	// empty file → error
	emptyPath := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(emptyPath, []byte("# just a comment\n"), 0600))
	_, err = readRoleFile(emptyPath)
	require.Error(t, err)

	// missing file → error
	_, err = readRoleFile(filepath.Join(dir, "nope.yaml"))
	require.Error(t, err)
}
