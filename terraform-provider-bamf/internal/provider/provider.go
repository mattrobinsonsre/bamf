// Package provider implements the Terraform provider for BAMF.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mattrobinsonsre/terraform-provider-bamf/internal/client"
)

// Ensure bamfProvider satisfies the provider.Provider interface.
var _ provider.Provider = &bamfProvider{}

type bamfProvider struct {
	version string
}

type bamfProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

// New returns the provider constructor Terraform calls.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &bamfProvider{version: version}
	}
}

func (p *bamfProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "bamf"
	resp.Version = p.version
}

func (p *bamfProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage a BAMF deployment (roles, RBAC, and more) as code via its REST API.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "BAMF API base URL, e.g. `https://bamf.example.com`. May also be set with `BAMF_API_URL`.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Admin session token (as issued by `bamf login`). May also be set with `BAMF_TOKEN`. Prefer the environment variable so the token is not stored in state.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *bamfProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg bamfProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv("BAMF_API_URL")
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	token := os.Getenv("BAMF_TOKEN")
	if !cfg.Token.IsNull() {
		token = cfg.Token.ValueString()
	}

	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Missing BAMF API endpoint",
			"Set the provider `endpoint` or the BAMF_API_URL environment variable.",
		)
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("token"),
			"Missing BAMF admin token",
			"Set the provider `token` or the BAMF_TOKEN environment variable.",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	c := client.New(endpoint, token)
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *bamfProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRoleResource,
	}
}

func (p *bamfProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
