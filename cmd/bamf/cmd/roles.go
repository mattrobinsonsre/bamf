// CLI reference: docs/reference/cli.md (Role management)
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type permissionsBlock struct {
	Labels map[string][]string `json:"labels"`
	Names  []string            `json:"names"`
}

// roleInfo mirrors the Python RoleResponse (services/bamf/api/models/roles.py).
type roleInfo struct {
	Name             string           `json:"name"`
	Description      string           `json:"description"`
	IsBuiltin        bool             `json:"is_builtin"`
	Allow            permissionsBlock `json:"allow"`
	Deny             permissionsBlock `json:"deny"`
	KubernetesGroups []string         `json:"kubernetes_groups"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Manage custom RBAC roles (admin)",
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles (built-in + custom)",
	RunE:  runRolesList,
}

var rolesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a role by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesGet,
}

var rolesCreateCmd = &cobra.Command{
	Use:   "create --from-file <file>",
	Short: "Create a custom role from a YAML or JSON file",
	RunE:  runRolesCreate,
}

var rolesUpdateCmd = &cobra.Command{
	Use:   "update <name> --from-file <file>",
	Short: "Update a custom role from a YAML or JSON file",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesUpdate,
}

var rolesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a custom role",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesDelete,
}

func init() {
	rootCmd.AddCommand(rolesCmd)
	rolesCmd.AddCommand(rolesListCmd, rolesGetCmd, rolesCreateCmd, rolesUpdateCmd, rolesDeleteCmd)

	rolesCreateCmd.Flags().String("from-file", "", "YAML or JSON file with the role definition (required)")
	_ = rolesCreateCmd.MarkFlagRequired("from-file")
	rolesUpdateCmd.Flags().String("from-file", "", "YAML or JSON file with the fields to update (required)")
	_ = rolesUpdateCmd.MarkFlagRequired("from-file")
}

// readRoleFile parses a YAML or JSON role file into a request body. YAML is a
// superset of JSON, so a single decode handles both.
func readRoleFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var body map[string]any
	if err := yaml.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("cannot parse %s (expected YAML or JSON): %w", path, err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return body, nil
}

func runRolesList(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var page struct {
		Items []roleInfo `json:"items"`
	}
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/roles", nil, &page); err != nil {
		return err
	}

	if jsonOutput {
		return printJSON(page.Items)
	}
	if len(page.Items) == 0 {
		fmt.Println("No roles found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tBUILTIN\tK8S GROUPS\tDESCRIPTION")
	for _, r := range page.Items {
		fmt.Fprintf(w, "%s\t%t\t%s\t%s\n", r.Name, r.IsBuiltin, joinOrDash(r.KubernetesGroups), r.Description)
	}
	return w.Flush()
}

func runRolesGet(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var r roleInfo
	if err := adminAPIRequest(ctx, http.MethodGet, "/api/v1/roles/"+args[0], nil, &r); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(r)
	}
	fmt.Printf("Name:        %s\n", r.Name)
	fmt.Printf("Built-in:    %t\n", r.IsBuiltin)
	fmt.Printf("Description: %s\n", r.Description)
	fmt.Printf("K8s groups:  %s\n", joinOrDash(r.KubernetesGroups))
	fmt.Printf("Allow:       names=%s labels=%v\n", joinOrDash(r.Allow.Names), r.Allow.Labels)
	fmt.Printf("Deny:        names=%s labels=%v\n", joinOrDash(r.Deny.Names), r.Deny.Labels)
	return nil
}

func runRolesCreate(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path, _ := cmd.Flags().GetString("from-file")
	body, err := readRoleFile(path)
	if err != nil {
		return err
	}

	var r roleInfo
	if err := adminAPIRequest(ctx, http.MethodPost, "/api/v1/roles", body, &r, http.StatusCreated); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(r)
	}
	fmt.Printf("Created role %s\n", r.Name)
	return nil
}

func runRolesUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path, _ := cmd.Flags().GetString("from-file")
	body, err := readRoleFile(path)
	if err != nil {
		return err
	}

	var r roleInfo
	if err := adminAPIRequest(ctx, http.MethodPatch, "/api/v1/roles/"+args[0], body, &r); err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(r)
	}
	fmt.Printf("Updated role %s\n", r.Name)
	return nil
}

func runRolesDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adminAPIRequest(ctx, http.MethodDelete, "/api/v1/roles/"+args[0], nil, nil,
		http.StatusOK, http.StatusNoContent); err != nil {
		return err
	}
	fmt.Printf("Deleted role %s\n", args[0])
	return nil
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}
