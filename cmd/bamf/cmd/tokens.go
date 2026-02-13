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

var tokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage join tokens for agents",
	Long: `Manage join tokens used by agents to register with BAMF.

Join tokens are single-use or limited-use tokens that allow
agents to authenticate and register with the cluster.`,
}

var tokensListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List join tokens",
	RunE:    runTokensList,
}

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new join token",
	Long: `Create a new join token for agent registration.

Examples:
  # Create a token that expires in 1 hour
  bamf tokens create --ttl 1h

  # Create a token with max 5 uses
  bamf tokens create --max-uses 5

  # Create a token with labels applied to registered agents
  bamf tokens create --labels env=prod,region=us-east-1`,
	RunE: runTokensCreate,
}

var tokensRevokeCmd = &cobra.Command{
	Use:   "revoke <token-name>",
	Short: "Revoke a join token",
	Args:  cobra.ExactArgs(1),
	RunE:  runTokensRevoke,
}

var (
	tokenTTL      string
	tokenMaxUses  int
	tokenLabels   string
	tokenName     string
)

func init() {
	rootCmd.AddCommand(tokensCmd)
	tokensCmd.AddCommand(tokensListCmd)
	tokensCmd.AddCommand(tokensCreateCmd)
	tokensCmd.AddCommand(tokensRevokeCmd)

	tokensCreateCmd.Flags().StringVar(&tokenTTL, "ttl", "1h", "token time-to-live (e.g., 1h, 24h, 7d)")
	tokensCreateCmd.Flags().IntVar(&tokenMaxUses, "max-uses", 0, "maximum number of uses (0 = unlimited)")
	tokensCreateCmd.Flags().StringVar(&tokenLabels, "labels", "", "labels to apply to registered agents (key=value,...)")
	tokensCreateCmd.Flags().StringVar(&tokenName, "name", "", "token name (auto-generated if not provided)")
}

type joinToken struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Token       string            `json:"token,omitempty"` // Only present on create
	ExpiresAt   time.Time         `json:"expires_at"`
	MaxUses     *int              `json:"max_uses,omitempty"`
	UseCount    int               `json:"use_count"`
	AgentLabels map[string]string `json:"agent_labels"`
	IsRevoked   bool              `json:"is_revoked"`
	CreatedAt   time.Time         `json:"created_at"`
	CreatedBy   string            `json:"created_by"`
}

func runTokensList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	api := resolveAPIURL()
	if api == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	u, _ := url.Parse(api)
	u.Path = "/api/v1/tokens"

	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	var result struct {
		Tokens []joinToken `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Tokens) == 0 {
		fmt.Println("No join tokens found.")
		return nil
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(result.Tokens, "", "  ")
		fmt.Println(string(out))
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATUS\tEXPIRES\tUSES\tCREATED BY")
		for _, t := range result.Tokens {
			status := "active"
			if t.IsRevoked {
				status = "revoked"
			} else if time.Now().After(t.ExpiresAt) {
				status = "expired"
			}

			uses := fmt.Sprintf("%d", t.UseCount)
			if t.MaxUses != nil {
				uses = fmt.Sprintf("%d/%d", t.UseCount, *t.MaxUses)
			}

			expires := t.ExpiresAt.Format("2006-01-02 15:04")
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				t.Name, status, expires, uses, t.CreatedBy)
		}
		w.Flush()
	}

	return nil
}

func runTokensCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	api := resolveAPIURL()
	if api == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	// Parse labels
	labels := make(map[string]string)
	if tokenLabels != "" {
		for _, pair := range strings.Split(tokenLabels, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}
	}

	reqBody := map[string]any{
		"ttl":          tokenTTL,
		"agent_labels": labels,
	}
	if tokenMaxUses > 0 {
		reqBody["max_uses"] = tokenMaxUses
	}
	if tokenName != "" {
		reqBody["name"] = tokenName
	}

	reqData, _ := json.Marshal(reqBody)

	u, _ := url.Parse(api)
	u.Path = "/api/v1/tokens"

	req, _ := http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(string(reqData)))
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	var token joinToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(token, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Join token created: %s\n\n", token.Name)
		fmt.Printf("Token: %s\n\n", token.Token)
		fmt.Printf("Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
		if token.MaxUses != nil {
			fmt.Printf("Max uses: %d\n", *token.MaxUses)
		}
		fmt.Println("\nUse this token to register an agent:")
		fmt.Printf("  bamf-agent join --token %s\n", token.Token)
	}

	return nil
}

func runTokensRevoke(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	api := resolveAPIURL()
	if api == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	tokenNameArg := args[0]

	u, _ := url.Parse(api)
	u.Path = fmt.Sprintf("/api/v1/tokens/%s/revoke", tokenNameArg)

	req, _ := http.NewRequestWithContext(ctx, "POST", u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("token not found: %s", tokenNameArg)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	fmt.Printf("Token %s revoked.\n", tokenNameArg)
	return nil
}
