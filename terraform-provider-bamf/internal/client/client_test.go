package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoleJSONShape(t *testing.T) {
	desc := "devs"
	role := Role{
		Name:             "developer",
		Description:      &desc,
		Allow:            PermissionsBlock{Labels: map[string][]string{"env": {"dev"}}, Names: []string{"jump"}},
		Deny:             PermissionsBlock{Labels: map[string][]string{}, Names: []string{"secrets"}},
		KubernetesGroups: []string{"view"},
	}
	b, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	// is_builtin must be omitted on the wire (create/update payload).
	if _, ok := got["is_builtin"]; ok {
		t.Error("is_builtin should be omitted when false")
	}
	if got["name"] != "developer" {
		t.Errorf("name = %v", got["name"])
	}
}

func TestClientCRUDPathsAndMethods(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer auth: %q", r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(Role{Name: "r1"})
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	ctx := context.Background()

	if _, err := c.GetRole(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/v1/roles/r1" {
		t.Errorf("get: %s %s", gotMethod, gotPath)
	}
	if _, err := c.UpdateRole(ctx, "r1", Role{Name: "r1"}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPatch { // update is PATCH, not PUT
		t.Errorf("update method = %s, want PATCH", gotMethod)
	}
	if err := c.DeleteRole(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
}

func TestClientNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "t").GetRole(context.Background(), "nope"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
