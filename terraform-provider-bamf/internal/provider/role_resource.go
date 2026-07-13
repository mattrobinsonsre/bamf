package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/mattrobinsonsre/terraform-provider-bamf/internal/client"
)

var (
	_ resource.Resource                = &roleResource{}
	_ resource.ResourceWithConfigure   = &roleResource{}
	_ resource.ResourceWithImportState = &roleResource{}
)

// NewRoleResource constructs the bamf_role resource.
func NewRoleResource() resource.Resource { return &roleResource{} }

type roleResource struct {
	client *client.Client
}

type permsModel struct {
	Labels types.Map  `tfsdk:"labels"`
	Names  types.List `tfsdk:"names"`
}

type roleResourceModel struct {
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	Allow            *permsModel  `tfsdk:"allow"`
	Deny             *permsModel  `tfsdk:"deny"`
	KubernetesGroups types.List   `tfsdk:"kubernetes_groups"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func permsBlockSchema(desc string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		MarkdownDescription: desc,
		Optional:            true,
		Attributes: map[string]schema.Attribute{
			"labels": schema.MapAttribute{
				MarkdownDescription: "Label selectors: label name → list of matching values.",
				Optional:            true,
				ElementType:         types.ListType{ElemType: types.StringType},
			},
			"names": schema.ListAttribute{
				MarkdownDescription: "Explicit resource names.",
				Optional:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A custom BAMF RBAC role. Built-in roles (admin, audit, everyone) are defined in code and cannot be managed here.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Role name (`[a-z][a-z0-9-]*`, max 63 chars). Changing it replaces the role.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Human-readable description.",
				Optional:            true,
			},
			"allow": permsBlockSchema("Resources this role grants access to."),
			"deny":  permsBlockSchema("Resources this role explicitly denies (deny wins over allow)."),
			"kubernetes_groups": schema.ListAttribute{
				MarkdownDescription: "Kubernetes groups the user is impersonated as for `kubernetes`-type resources.",
				Optional:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

// ── model ⇄ API conversions ────────────────────────────────────────────────

func permsToAPI(ctx context.Context, m *permsModel) (client.PermissionsBlock, error) {
	block := client.PermissionsBlock{Labels: map[string][]string{}, Names: []string{}}
	if m == nil {
		return block, nil
	}
	if !m.Labels.IsNull() {
		raw := map[string][]string{}
		if diags := m.Labels.ElementsAs(ctx, &raw, false); diags.HasError() {
			return block, errors.New("invalid labels")
		}
		block.Labels = raw
	}
	if !m.Names.IsNull() {
		var names []string
		if diags := m.Names.ElementsAs(ctx, &names, false); diags.HasError() {
			return block, errors.New("invalid names")
		}
		block.Names = names
	}
	return block, nil
}

func permsFromAPI(ctx context.Context, b client.PermissionsBlock) (*permsModel, error) {
	// Represent an empty block as null, and each empty inner attribute as null,
	// so the state round-trips cleanly with config that omits `allow`/`deny` or
	// their `labels`/`names` (Terraform requires state to match config exactly
	// for these user-owned, non-computed attributes).
	if len(b.Labels) == 0 && len(b.Names) == 0 {
		return nil, nil
	}
	m := &permsModel{
		Labels: types.MapNull(types.ListType{ElemType: types.StringType}),
		Names:  types.ListNull(types.StringType),
	}
	if len(b.Labels) > 0 {
		labels, d := types.MapValueFrom(ctx, types.ListType{ElemType: types.StringType}, b.Labels)
		if d.HasError() {
			return nil, errors.New("labels conversion")
		}
		m.Labels = labels
	}
	if len(b.Names) > 0 {
		names, d := types.ListValueFrom(ctx, types.StringType, b.Names)
		if d.HasError() {
			return nil, errors.New("names conversion")
		}
		m.Names = names
	}
	return m, nil
}

func (r *roleResource) modelToRole(ctx context.Context, m roleResourceModel) (client.Role, error) {
	allow, err := permsToAPI(ctx, m.Allow)
	if err != nil {
		return client.Role{}, err
	}
	deny, err := permsToAPI(ctx, m.Deny)
	if err != nil {
		return client.Role{}, err
	}
	var kg []string
	if !m.KubernetesGroups.IsNull() {
		if diags := m.KubernetesGroups.ElementsAs(ctx, &kg, false); diags.HasError() {
			return client.Role{}, errors.New("invalid kubernetes_groups")
		}
	}
	role := client.Role{Name: m.Name.ValueString(), Allow: allow, Deny: deny, KubernetesGroups: kg}
	if !m.Description.IsNull() {
		d := m.Description.ValueString()
		role.Description = &d
	}
	return role, nil
}

func (r *roleResource) roleToModel(ctx context.Context, role *client.Role) (roleResourceModel, error) {
	m := roleResourceModel{Name: types.StringValue(role.Name)}
	if role.Description != nil {
		m.Description = types.StringValue(*role.Description)
	} else {
		m.Description = types.StringNull()
	}
	allow, err := permsFromAPI(ctx, role.Allow)
	if err != nil {
		return m, err
	}
	deny, err := permsFromAPI(ctx, role.Deny)
	if err != nil {
		return m, err
	}
	m.Allow, m.Deny = allow, deny
	if len(role.KubernetesGroups) == 0 {
		m.KubernetesGroups = types.ListNull(types.StringType)
	} else {
		kg, d := types.ListValueFrom(ctx, types.StringType, role.KubernetesGroups)
		if d.HasError() {
			return m, errors.New("kubernetes_groups conversion")
		}
		m.KubernetesGroups = kg
	}
	return m, nil
}

// ── CRUD ────────────────────────────────────────────────────────────────────

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role, err := r.modelToRole(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid role", err.Error())
		return
	}
	if _, err := r.client.CreateRole(ctx, role); err != nil {
		resp.Diagnostics.AddError("Create role failed", err.Error())
		return
	}
	// State mirrors the plan: every attribute is user-owned (nothing is
	// server-generated), and the API stores exactly what we sent.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role, err := r.client.GetRole(ctx, state.Name.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read role failed", err.Error())
		return
	}
	newState, err := r.roleToModel(ctx, role)
	if err != nil {
		resp.Diagnostics.AddError("Decode role failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role, err := r.modelToRole(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid role", err.Error())
		return
	}
	if _, err := r.client.UpdateRole(ctx, plan.Name.ValueString(), role); err != nil {
		resp.Diagnostics.AddError("Update role failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRole(ctx, state.Name.ValueString()); err != nil && !errors.Is(err, client.ErrNotFound) {
		resp.Diagnostics.AddError("Delete role failed", err.Error())
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
