package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	resourcesType   string
	resourcesLabels string
)

var resourcesCmd = &cobra.Command{
	Use:     "resources",
	Aliases: []string{"ls", "list"},
	Short:   "List available resources",
	Long: `List resources you have access to.

Resources include SSH servers, Kubernetes clusters, databases,
and web applications registered with BAMF.

Examples:
  # List all accessible resources
  bamf resources

  # Filter by type
  bamf resources --type ssh
  bamf resources --type kubernetes
  bamf resources --type database

  # Filter by labels
  bamf resources --labels env=prod,team=platform`,
	RunE: runResources,
}

func init() {
	rootCmd.AddCommand(resourcesCmd)
	resourcesCmd.Flags().StringVarP(&resourcesType, "type", "t", "", "filter by resource type (ssh, kubernetes, database, web)")
	resourcesCmd.Flags().StringVarP(&resourcesLabels, "labels", "l", "", "filter by labels (key=value,...)")
}

type resource struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	ResourceType string            `json:"resource_type"`
	Labels       map[string]string `json:"labels"`
	Status       string            `json:"status"`
	AgentName    string            `json:"agent_name,omitempty"`
}

func runResources(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load credentials
	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w\nRun 'bamf login' to authenticate", err)
	}

	if time.Now().After(creds.ExpiresAt) {
		return fmt.Errorf("credentials expired. Run 'bamf login' to refresh")
	}

	// Build API URL
	api := resolveAPIURL()
	if api == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	u, err := url.Parse(api)
	if err != nil {
		return err
	}
	u.Path = "/api/v1/resources"

	q := u.Query()
	if resourcesType != "" {
		q.Set("type", resourcesType)
	}
	if resourcesLabels != "" {
		q.Set("labels", resourcesLabels)
	}
	u.RawQuery = q.Encode()

	// Make request
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	var result struct {
		Resources []resource `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Resources) == 0 {
		fmt.Println("No resources found.")
		return nil
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(result.Resources, "", "  ")
		fmt.Println(string(out))
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tTYPE\tSTATUS\tLABELS\tAGENT")
		for _, r := range result.Resources {
			labels := formatLabels(r.Labels)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				r.Name, r.ResourceType, r.Status, labels, r.AgentName)
		}
		w.Flush()
	}

	return nil
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}
