// CLI reference: docs/reference/cli.md (Outposts)
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

// ── Outpost tokens ────────────────────────────────────────────────────────────

type outpostToken struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OutpostName string    `json:"outpost_name"`
	Region      *string   `json:"region"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxUses     *int      `json:"max_uses"`
	UseCount    int       `json:"use_count"`
	IsRevoked   bool      `json:"is_revoked"`
	CreatedBy   string    `json:"created_by"`
}

type outpostTokenCreateResp struct {
	outpostToken
	Token string `json:"token"`
}

type outpostInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Region    *string   `json:"region"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	outpostTokenOutpost string
	outpostTokenRegion  string
	outpostTokenTTL     int
	outpostTokenMaxUses int
)

var outpostTokensCmd = &cobra.Command{
	Use:     "outpost-tokens",
	Aliases: []string{"outpost-token"},
	Short:   "Manage outpost join tokens (admin)",
}

var outpostTokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List outpost join tokens",
	RunE:  runOutpostTokensList,
}

var outpostTokensCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an outpost join token",
	Args:  cobra.ExactArgs(1),
	RunE:  runOutpostTokensCreate,
}

var outpostTokensRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke an outpost join token by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runOutpostTokensRevoke,
}

// ── Outposts ──────────────────────────────────────────────────────────────────

var outpostsCmd = &cobra.Command{
	Use:   "outposts",
	Short: "Manage registered outposts (admin)",
}

var outpostsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered outposts",
	RunE:  runOutpostsList,
}

var outpostsDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Deregister an outpost by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runOutpostsDelete,
}

func init() {
	outpostTokensCreateCmd.Flags().StringVar(&outpostTokenOutpost, "outpost", "", "Outpost name this token registers (required)")
	outpostTokensCreateCmd.Flags().StringVar(&outpostTokenRegion, "region", "", "Human-readable region label")
	outpostTokensCreateCmd.Flags().IntVar(&outpostTokenTTL, "ttl", 24, "Hours until the token expires")
	outpostTokensCreateCmd.Flags().IntVar(&outpostTokenMaxUses, "max-uses", 0, "Max uses (0 = unlimited)")
	_ = outpostTokensCreateCmd.MarkFlagRequired("outpost")

	outpostTokensCmd.AddCommand(outpostTokensListCmd, outpostTokensCreateCmd, outpostTokensRevokeCmd)
	outpostsCmd.AddCommand(outpostsListCmd, outpostsDeleteCmd)
	rootCmd.AddCommand(outpostTokensCmd, outpostsCmd)
}

func runOutpostTokensList(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []outpostToken `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/outpost-tokens", nil, &page); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No outpost tokens found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tOUTPOST\tSTATUS\tEXPIRES\tUSES\tCREATED BY")
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
			t.Name, t.OutpostName, status, t.ExpiresAt.Format("2006-01-02 15:04"), uses, t.CreatedBy)
	}
	return w.Flush()
}

func runOutpostTokensCreate(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body := map[string]any{
		"name":             args[0],
		"outpost_name":     outpostTokenOutpost,
		"expires_in_hours": outpostTokenTTL,
	}
	if outpostTokenRegion != "" {
		body["region"] = outpostTokenRegion
	}
	if outpostTokenMaxUses > 0 {
		body["max_uses"] = outpostTokenMaxUses
	}

	var created outpostTokenCreateResp
	if err := adminAPIRequest(ctx, http.MethodPost, "/api/v1/outpost-tokens", body, &created, http.StatusCreated); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(created)
	}
	fmt.Printf("Created outpost token %q for outpost %q.\n\n", created.Name, created.OutpostName)
	fmt.Printf("  %s\n\n", created.Token)
	fmt.Println("This token is shown only once — store it securely (e.g. the outpost's join Secret).")
	return nil
}

func runOutpostTokensRevoke(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/api/v1/outpost-tokens/%s/revoke", args[0])
	if err := adminAPIRequest(ctx, http.MethodPost, path, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Revoked outpost token %q.\n", args[0])
	return nil
}

func runOutpostsList(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []outpostInfo `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/outposts", nil, &page); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No outposts registered.")
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

func runOutpostsDelete(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/api/v1/outposts/%s", args[0])
	if err := adminAPIRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Deregistered outpost %q.\n", args[0])
	return nil
}
