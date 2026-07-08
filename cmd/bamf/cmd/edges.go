// CLI reference: docs/reference/cli.md (Edges)
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// ── Edge tokens ────────────────────────────────────────────────────────────

type edgeToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	EdgeName  string    `json:"edge_name"`
	Region    *string   `json:"region"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   *int      `json:"max_uses"`
	UseCount  int       `json:"use_count"`
	IsRevoked bool      `json:"is_revoked"`
	CreatedBy string    `json:"created_by"`
}

type edgeTokenCreateResp struct {
	edgeToken
	Token string `json:"token"`
}

type edgeInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Region    *string   `json:"region"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	edgeTokenEdge    string
	edgeTokenRegion  string
	edgeTokenTTL     int
	edgeTokenMaxUses int
)

var edgeTokensCmd = &cobra.Command{
	Use:     "edge-tokens",
	Aliases: []string{"edge-token"},
	Short:   "Manage edge join tokens (admin)",
}

var edgeTokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List edge join tokens",
	RunE:  runEdgeTokensList,
}

var edgeTokensCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an edge join token",
	Args:  cobra.ExactArgs(1),
	RunE:  runEdgeTokensCreate,
}

var edgeTokensRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke an edge join token by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runEdgeTokensRevoke,
}

// ── Edges ──────────────────────────────────────────────────────────────────

var edgesCmd = &cobra.Command{
	Use:   "edges",
	Short: "Manage registered edges (admin)",
}

var edgesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered edges",
	RunE:  runEdgesList,
}

var edgesDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Deregister an edge by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runEdgesDelete,
}

func init() {
	edgeTokensCreateCmd.Flags().StringVar(&edgeTokenEdge, "edge", "", "Edge name this token registers (required)")
	edgeTokensCreateCmd.Flags().StringVar(&edgeTokenRegion, "region", "", "Human-readable region label")
	edgeTokensCreateCmd.Flags().IntVar(&edgeTokenTTL, "ttl", 24, "Hours until the token expires")
	edgeTokensCreateCmd.Flags().IntVar(&edgeTokenMaxUses, "max-uses", 0, "Max uses (0 = unlimited)")
	_ = edgeTokensCreateCmd.MarkFlagRequired("edge")

	edgeTokensCmd.AddCommand(edgeTokensListCmd, edgeTokensCreateCmd, edgeTokensRevokeCmd)
	edgesCmd.AddCommand(edgesListCmd, edgesDeleteCmd)
	rootCmd.AddCommand(edgeTokensCmd, edgesCmd)
}

func runEdgeTokensList(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []edgeToken `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/edge-tokens", nil, &page); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No edge tokens found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tEDGE\tSTATUS\tEXPIRES\tUSES\tCREATED BY")
	for _, t := range page.Items {
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.Name, t.EdgeName, status, t.ExpiresAt.Format("2006-01-02 15:04"), uses, t.CreatedBy)
	}
	return w.Flush()
}

func runEdgeTokensCreate(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body := map[string]any{
		"name":             args[0],
		"edge_name":        edgeTokenEdge,
		"expires_in_hours": edgeTokenTTL,
	}
	if edgeTokenRegion != "" {
		body["region"] = edgeTokenRegion
	}
	if edgeTokenMaxUses > 0 {
		body["max_uses"] = edgeTokenMaxUses
	}

	var created edgeTokenCreateResp
	if err := adminAPIRequest(ctx, http.MethodPost, "/api/v1/edge-tokens", body, &created, http.StatusCreated); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(created)
	}
	fmt.Printf("Created edge token %q for edge %q.\n\n", created.Name, created.EdgeName)
	fmt.Printf("  %s\n\n", created.Token)
	fmt.Println("This token is shown only once — store it securely (e.g. the edge's join Secret).")
	return nil
}

func runEdgeTokensRevoke(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/api/v1/edge-tokens/%s/revoke", args[0])
	if err := adminAPIRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Revoked edge token %q.\n", args[0])
	return nil
}

func runEdgesList(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []edgeInfo `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/edges", nil, &page); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No edges registered.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tREGION\tACTIVE\tID")
	for _, o := range page.Items {
		region := "-"
		if o.Region != nil && *o.Region != "" {
			region = *o.Region
		}
		fmt.Fprintf(w, "%s\t%s\t%t\t%s\n", o.Name, region, o.IsActive, o.ID)
	}
	return w.Flush()
}

func runEdgesDelete(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/api/v1/edges/%s", args[0])
	if err := adminAPIRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Deregistered edge %q.\n", args[0])
	return nil
}
