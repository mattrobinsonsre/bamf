package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// ── Tests: bamfDir ──────────────────────────────────────────────────

func TestBamfDir_ReturnsHomeBamf(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := bamfDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".bamf"), dir)
}

func TestBamfDir_DifferentHomes(t *testing.T) {
	tests := []struct {
		name string
		home string
		want string
	}{
		{
			name: "standard home",
			home: "/Users/alice",
			want: "/Users/alice/.bamf",
		},
		{
			name: "root home",
			home: "/root",
			want: "/root/.bamf",
		},
		{
			name: "linux home",
			home: "/home/bob",
			want: "/home/bob/.bamf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", tt.home)
			dir, err := bamfDir()
			require.NoError(t, err)
			require.Equal(t, tt.want, dir)
		})
	}
}

// ── Tests: ensureBamfDir ────────────────────────────────────────────

func TestEnsureBamfDir_CreatesDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := ensureBamfDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".bamf"), dir)

	// Verify .bamf directory was created
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())

	// Verify keys subdirectory was created
	keysDir := filepath.Join(dir, "keys")
	info, err = os.Stat(keysDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestEnsureBamfDir_Idempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Call twice — should not error on second call
	dir1, err := ensureBamfDir()
	require.NoError(t, err)

	dir2, err := ensureBamfDir()
	require.NoError(t, err)

	require.Equal(t, dir1, dir2)
}

// ── Tests: execSSHBinary argument construction ──────────────────────

// We cannot test execSSHBinary directly because it calls execReplace/os.Executable,
// but we can test the argument construction logic by verifying the components.
// The function builds: [binary, "-o", "ProxyCommand=<exe> pipe %h %r", "-o", "UserKnownHostsFile=<bamfDir>/known_hosts", ...userArgs]

func TestSSHProxyCommandConstruction(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath, err := bamfDir()
	require.NoError(t, err)

	expectedKnownHosts := filepath.Join(bamfPath, "known_hosts")
	require.Equal(t, filepath.Join(home, ".bamf", "known_hosts"), expectedKnownHosts)
}

// ── Tests: runSSH help detection ────────────────────────────────────

func TestRunSSH_HelpFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long help", args: []string{"--help"}},
		{name: "short help", args: []string{"-h"}},
		{name: "no args", args: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These should not return an error — they should print help
			err := runSSH(sshCmd, tt.args)
			require.NoError(t, err)
		})
	}
}

// ── Tests: runSCP help detection ────────────────────────────────────

func TestRunSCP_HelpFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long help", args: []string{"--help"}},
		{name: "short help", args: []string{"-h"}},
		{name: "no args", args: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSCP(scpCmd, tt.args)
			require.NoError(t, err)
		})
	}
}

// ── Tests: runSFTP help detection ───────────────────────────────────

func TestRunSFTP_HelpFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long help", args: []string{"--help"}},
		{name: "short help", args: []string{"-h"}},
		{name: "no args", args: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSFTP(sftpCmd, tt.args)
			require.NoError(t, err)
		})
	}
}

// ── Tests: formatLabels ─────────────────────────────────────────────

func TestFormatLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   "-",
		},
		{
			name:   "nil labels",
			labels: nil,
			want:   "-",
		},
		{
			name:   "single label",
			labels: map[string]string{"env": "prod"},
			want:   "env=prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatLabels(tt.labels)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestFormatLabels_MultipleLabels(t *testing.T) {
	labels := map[string]string{"env": "prod", "team": "platform"}
	result := formatLabels(labels)

	// Map iteration order is not guaranteed, so check both possibilities
	require.True(t,
		result == "env=prod,team=platform" || result == "team=platform,env=prod",
		"unexpected label format: %s", result)
}

// ── Tests: initConfig ───────────────────────────────────────────────

func TestInitConfig_DefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Reset cfgFile
	oldCfg := cfgFile
	cfgFile = ""
	defer func() { cfgFile = oldCfg }()

	initConfig()

	require.Equal(t, filepath.Join(home, ".bamf", "config.yaml"), cfgFile)
}

func TestInitConfig_CustomPath(t *testing.T) {
	oldCfg := cfgFile
	cfgFile = "/custom/config.yaml"
	defer func() { cfgFile = oldCfg }()

	initConfig()

	// Should remain unchanged when already set
	require.Equal(t, "/custom/config.yaml", cfgFile)
}

// ── Tests: resolveAPIURL ────────────────────────────────────────────

func TestResolveAPIURL_FlagFirst(t *testing.T) {
	t.Setenv("BAMF_API_URL", "https://from-env.example.com")
	t.Setenv("HOME", t.TempDir()) // no saved creds

	oldAPIURL := apiURL
	apiURL = "https://from-flag.example.com"
	defer func() { apiURL = oldAPIURL }()

	result := resolveAPIURL()
	require.Equal(t, "https://from-flag.example.com", result)
}

func TestResolveAPIURL_EnvSecond(t *testing.T) {
	t.Setenv("BAMF_API_URL", "https://from-env.example.com")
	t.Setenv("HOME", t.TempDir()) // no saved creds

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	result := resolveAPIURL()
	require.Equal(t, "https://from-env.example.com", result)
}

func TestResolveAPIURL_SavedCredsFallback(t *testing.T) {
	t.Setenv("BAMF_API_URL", "")

	home := t.TempDir()
	t.Setenv("HOME", home)

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	// Write a credentials file with an API URL
	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := `{"session_token":"tok","api_url":"https://from-creds.example.com","expires_at":"2027-01-01T00:00:00Z"}`
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte(creds), 0600))

	result := resolveAPIURL()
	require.Equal(t, "https://from-creds.example.com", result)
}

func TestResolveAPIURL_EmptyWhenNoneConfigured(t *testing.T) {
	t.Setenv("BAMF_API_URL", "")
	t.Setenv("HOME", t.TempDir()) // no saved creds

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	result := resolveAPIURL()
	require.Empty(t, result)
}

// ── Tests: parseTTLToHours ──────────────────────────────────────────

func TestParseTTLToHours(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "one hour", input: "1h", want: 1},
		{name: "24 hours", input: "24h", want: 24},
		{name: "half hour rounds up", input: "30m", want: 1},
		{name: "10 minutes rounds up", input: "10m", want: 1},
		{name: "7 days", input: "7d", want: 168},
		{name: "1 day", input: "1d", want: 24},
		{name: "30 days", input: "30d", want: 720},
		{name: "invalid", input: "foobar", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "negative day", input: "-1d", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTTLToHours(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

// ── Tests: signalDaemonResult ───────────────────────────────────────

func TestSignalDaemonResult_NotDaemon(t *testing.T) {
	// Should be a no-op when isDaemon is false
	signalDaemonResult(false, nil, "5432")
	signalDaemonResult(false, os.ErrNotExist, "")
}

// ── Tests: version command output ───────────────────────────────────

func TestVersionVars_Defaults(t *testing.T) {
	// The package-level vars should have their default values
	require.Equal(t, "dev", Version)
	require.Equal(t, "unknown", GitCommit)
	require.Equal(t, "unknown", BuildTime)
}
