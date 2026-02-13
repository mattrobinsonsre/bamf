package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List registered agents",
	Long: `List agents registered with the BAMF cluster.

Agents are deployed alongside target resources and handle
connections proxied through BAMF.

Examples:
  # List all agents
  bamf agents

  # JSON output
  bamf agents --json`,
	RunE: runAgents,
}

func init() {
	rootCmd.AddCommand(agentsCmd)
}

type agent struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Status        string            `json:"status"`
	Labels        map[string]string `json:"labels"`
	LastHeartbeat *time.Time        `json:"last_heartbeat,omitempty"`
	ResourceCount int               `json:"resource_count"`
}

func runAgents(cmd *cobra.Command, args []string) error {
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
	u.Path = "/api/v1/agents"

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
		Agents []agent `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Agents) == 0 {
		fmt.Println("No agents registered.")
		return nil
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(result.Agents, "", "  ")
		fmt.Println(string(out))
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATUS\tLAST SEEN\tRESOURCES\tLABELS")
		for _, a := range result.Agents {
			lastSeen := "-"
			if a.LastHeartbeat != nil {
				lastSeen = time.Since(*a.LastHeartbeat).Round(time.Second).String() + " ago"
			}
			labels := formatLabels(a.Labels)
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
				a.Name, a.Status, lastSeen, a.ResourceCount, labels)
		}
		w.Flush()
	}

	return nil
}
