package cmd

// CLI reference: docs/reference/cli.md (Kubernetes section)
// Guide: docs/guides/kubernetes.md

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var kubeCmd = &cobra.Command{
	Use:   "kube",
	Short: "Kubernetes cluster access via BAMF",
	Long: `Manage Kubernetes cluster access through BAMF.

Subcommands:
  login           Write kubeconfig entry for a K8s cluster
  credentials     Exec credential plugin for kubectl (internal use)`,
}

var kubeLoginCmd = &cobra.Command{
	Use:   "login <resource-name>",
	Short: "Write kubeconfig entry for a Kubernetes cluster",
	Long: `Write a kubeconfig context that routes kubectl through BAMF.

After running this command, use kubectl with the generated context:

  bamf kube login prod-cluster
  kubectl --context bamf-prod-cluster get pods

The kubeconfig entry uses an exec credential plugin (bamf kube-credentials)
to authenticate kubectl requests with your BAMF session token.

Examples:
  # Set up access to a cluster
  bamf kube login prod-cluster

  # Use the cluster
  kubectl --context bamf-prod-cluster get namespaces
  helm --kube-context bamf-prod-cluster list`,
	Args: cobra.ExactArgs(1),
	RunE: runKubeLogin,
}

var kubeCredentialsCmd = &cobra.Command{
	Use:    "kube-credentials",
	Short:  "Exec credential plugin for kubectl",
	Long:   "Internal command used by kubectl exec credential plugin. Outputs ExecCredential JSON.",
	Hidden: true,
	RunE:   runKubeCredentials,
}

func init() {
	rootCmd.AddCommand(kubeCmd)
	rootCmd.AddCommand(kubeCredentialsCmd)
	kubeCmd.AddCommand(kubeLoginCmd)
}

func runKubeLogin(cmd *cobra.Command, args []string) error {
	resourceName := args[0]

	// Load credentials to verify we're logged in
	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w\nRun 'bamf login' to authenticate", err)
	}

	if time.Now().After(creds.ExpiresAt) {
		return fmt.Errorf("credentials expired. Run 'bamf login' to refresh")
	}

	apiURL := creds.APIURL
	if apiURL == "" {
		apiURL = resolveAPIURL()
	}
	if apiURL == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	// Context/cluster/user names use bamf- prefix to avoid collisions
	contextName := fmt.Sprintf("bamf-%s", resourceName)
	clusterName := contextName
	userName := contextName

	// K8s API URL is the BAMF API with /api/v1/kube/{resource} prefix
	serverURL := fmt.Sprintf("%s/api/v1/kube/%s", apiURL, resourceName)

	// Find the bamf binary path for the exec plugin
	bamfBin, err := os.Executable()
	if err != nil {
		bamfBin = "bamf" // Fallback to PATH lookup
	}

	// Build kubeconfig structures
	newCluster := &clientcmdapi.Cluster{
		Server: serverURL,
	}

	newUser := &clientcmdapi.AuthInfo{
		Exec: &clientcmdapi.ExecConfig{
			APIVersion:      "client.authentication.k8s.io/v1beta1",
			Command:         bamfBin,
			Args:            []string{"kube-credentials"},
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		},
	}

	newContext := &clientcmdapi.Context{
		Cluster:  clusterName,
		AuthInfo: userName,
	}

	// Load existing kubeconfig
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := loadingRules.Load()
	if err != nil {
		// Start with empty config if none exists
		config = clientcmdapi.NewConfig()
	}

	// Merge in the new entries
	config.Clusters[clusterName] = newCluster
	config.AuthInfos[userName] = newUser
	config.Contexts[contextName] = newContext

	// Write back
	configPath := loadingRules.GetDefaultFilename()
	if err := clientcmd.WriteToFile(*config, configPath); err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	fmt.Printf("Kubeconfig context '%s' written to %s\n", contextName, configPath)
	fmt.Printf("\nUsage:\n")
	fmt.Printf("  kubectl --context %s get namespaces\n", contextName)
	fmt.Printf("  kubectl config use-context %s\n", contextName)
	return nil
}

func runKubeCredentials(cmd *cobra.Command, args []string) error {
	// Load credentials
	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w\nRun 'bamf login' to authenticate", err)
	}

	if time.Now().After(creds.ExpiresAt) {
		return fmt.Errorf("credentials expired. Run 'bamf login' to refresh")
	}

	// Build ExecCredential response
	execCred := map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind":       "ExecCredential",
		"status": map[string]any{
			"token":               creds.SessionToken,
			"expirationTimestamp": creds.ExpiresAt.Format(time.RFC3339),
		},
	}

	return json.NewEncoder(os.Stdout).Encode(execCred)
}
