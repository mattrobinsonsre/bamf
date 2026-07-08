// CLI reference: docs/reference/cli.md (User management)
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type userRole struct {
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
}

// userInfo mirrors the Python UserResponse (services/bamf/api/models/users.py).
type userInfo struct {
	Email     string     `json:"email"`
	IsActive  bool       `json:"is_active"`
	Roles     []userRole `json:"roles"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// adminAPIRequest performs an authenticated JSON request against the API. When
// body is non-nil it is sent as JSON; when out is non-nil the response is
// decoded into it. A non-accepted status returns the API's {"detail": ...}.
func adminAPIRequest(ctx context.Context, method, path string, body, out any, okStatus ...int) error {
	creds, err := loadCredentials()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}
	api := resolveAPIURL()
	if api == "" {
		return fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}
	u, err := url.Parse(api)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	u.Path = path

	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if len(okStatus) == 0 {
		okStatus = []int{http.StatusOK}
	}
	if !slices.Contains(okStatus, resp.StatusCode) {
		return apiErrorFromResponse(resp)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

// apiErrorFromResponse turns a non-2xx response into an error, preferring the
// FastAPI {"detail": "..."} message over the bare status line.
func apiErrorFromResponse(resp *http.Response) error {
	var e struct {
		Detail string `json:"detail"`
	}
	if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Detail != "" {
		return fmt.Errorf("API error (%s): %s", resp.Status, e.Detail)
	}
	return fmt.Errorf("API error: %s", resp.Status)
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage local users (admin)",
}

var usersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	RunE:  runUsersList,
}

var usersGetCmd = &cobra.Command{
	Use:   "get <email>",
	Short: "Get a user by email",
	Args:  cobra.ExactArgs(1),
	RunE:  runUsersGet,
}

var usersCreateCmd = &cobra.Command{
	Use:   "create <email>",
	Short: "Create a local user",
	Args:  cobra.ExactArgs(1),
	RunE:  runUsersCreate,
}

var usersUpdateCmd = &cobra.Command{
	Use:   "update <email>",
	Short: "Update a user (roles, password, active status)",
	Args:  cobra.ExactArgs(1),
	RunE:  runUsersUpdate,
}

var usersDeleteCmd = &cobra.Command{
	Use:   "delete <email>",
	Short: "Delete a user",
	Args:  cobra.ExactArgs(1),
	RunE:  runUsersDelete,
}

func init() {
	rootCmd.AddCommand(usersCmd)
	usersCmd.AddCommand(usersListCmd, usersGetCmd, usersCreateCmd, usersUpdateCmd, usersDeleteCmd)

	usersCreateCmd.Flags().String("password", "", "password for local auth (omit for SSO-only)")
	usersCreateCmd.Flags().StringSlice("role", nil, "role to assign (repeatable)")

	usersUpdateCmd.Flags().String("password", "", "set a new password")
	usersUpdateCmd.Flags().StringSlice("role", nil, "replace the user's roles (repeatable)")
	usersUpdateCmd.Flags().Bool("active", false, "mark the user active")
	usersUpdateCmd.Flags().Bool("inactive", false, "mark the user inactive")
}

func runUsersList(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []userInfo `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/users", nil, &page); err != nil {
		return err
	}

	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No users found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EMAIL\tACTIVE\tROLES\tCREATED")
	for _, u := range page.Items {
		fmt.Fprintf(w, "%s\t%t\t%s\t%s\n", u.Email, u.IsActive, formatUserRoles(u.Roles), u.CreatedAt.Format("2006-01-02"))
	}
	return w.Flush()
}

func runUsersGet(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var u userInfo
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/users/"+args[0], nil, &u); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(u)
	}
	fmt.Printf("Email:   %s\n", u.Email)
	fmt.Printf("Active:  %t\n", u.IsActive)
	fmt.Printf("Roles:   %s\n", formatUserRoles(u.Roles))
	fmt.Printf("Created: %s\n", u.CreatedAt.Format(time.RFC3339))
	return nil
}

func runUsersCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	password, _ := cmd.Flags().GetString("password")
	roles, _ := cmd.Flags().GetStringSlice("role")

	body := map[string]any{"email": args[0], "roles": roles}
	if password != "" {
		body["password"] = password
	}

	var u userInfo
	if err := adminAPIRequest(ctx, http.MethodPost, "/api/v1/users", body, &u, http.StatusCreated); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(u)
	}
	fmt.Printf("Created user %s\n", u.Email)
	return nil
}

func runUsersUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	active, _ := cmd.Flags().GetBool("active")
	inactive, _ := cmd.Flags().GetBool("inactive")
	if active && inactive {
		return fmt.Errorf("--active and --inactive are mutually exclusive")
	}

	body := map[string]any{}
	if cmd.Flags().Changed("password") {
		password, _ := cmd.Flags().GetString("password")
		body["password"] = password
	}
	if cmd.Flags().Changed("role") {
		roles, _ := cmd.Flags().GetStringSlice("role")
		body["roles"] = roles
	}
	if active {
		body["is_active"] = true
	}
	if inactive {
		body["is_active"] = false
	}
	if len(body) == 0 {
		return fmt.Errorf("nothing to update: pass --password, --role, --active, or --inactive")
	}

	var u userInfo
	if err := adminAPIRequest(ctx, http.MethodPatch, "/api/v1/users/"+args[0], body, &u); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(u)
	}
	fmt.Printf("Updated user %s\n", u.Email)
	return nil
}

func runUsersDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adminAPIRequest(ctx, http.MethodDelete, "/api/v1/users/"+args[0], nil, nil,
		http.StatusOK, http.StatusNoContent); err != nil {
		return err
	}
	fmt.Printf("Deleted user %s\n", args[0])
	return nil
}

func formatUserRoles(roles []userRole) string {
	if len(roles) == 0 {
		return "-"
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return strings.Join(names, ",")
}

func printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
