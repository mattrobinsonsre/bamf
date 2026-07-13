package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestProviderSchema(t *testing.T) {
	resp := &provider.SchemaResponse{}
	New("test")().Schema(context.Background(), provider.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema diagnostics: %v", resp.Diagnostics)
	}
	for _, attr := range []string{"endpoint", "token"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("provider schema missing attribute %q", attr)
		}
	}
}

func TestRoleResourceSchema(t *testing.T) {
	ctx := context.Background()
	resp := &resource.SchemaResponse{}
	NewRoleResource().Schema(ctx, resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("role schema diagnostics: %v", resp.Diagnostics)
	}
	if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatalf("role schema invalid: %v", d)
	}
	for _, attr := range []string{"name", "description", "allow", "deny", "kubernetes_groups"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("role schema missing attribute %q", attr)
		}
	}
}

func TestRoleResourceMetadata(t *testing.T) {
	resp := &resource.MetadataResponse{}
	NewRoleResource().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "bamf"}, resp)
	if resp.TypeName != "bamf_role" {
		t.Errorf("type name = %q, want bamf_role", resp.TypeName)
	}
}
