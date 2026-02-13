package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPost_Success(t *testing.T) {
	type resp struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
			return
		}
		if body["input"] != "hello" {
			t.Errorf("expected input=hello, got %s", body["input"])
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp{Name: "test", ID: 42}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	var got resp
	err := client.Post(context.Background(), "/test", map[string]string{"input": "hello"}, &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "test" || got.ID != 42 {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestGet_Success(t *testing.T) {
	type resp struct {
		Items []string `json:"items"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp{Items: []string{"a", "b"}}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	var got resp
	err := client.Get(context.Background(), "/items", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Items) != 2 || got.Items[0] != "a" {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestPost_NilResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	err := client.Post(context.Background(), "/fire-and-forget", map[string]string{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestErrorResponse_FastAPIDetail(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantDetail string
	}{
		{
			name:       "404 with detail",
			statusCode: 404,
			body:       `{"detail": "Agent not found"}`,
			wantDetail: "Agent not found",
		},
		{
			name:       "401 with detail",
			statusCode: 401,
			body:       `{"detail": "Invalid join token"}`,
			wantDetail: "Invalid join token",
		},
		{
			name:       "500 plain text",
			statusCode: 500,
			body:       "Internal Server Error",
			wantDetail: "Internal Server Error",
		},
		{
			name:       "400 empty body",
			statusCode: 400,
			body:       "",
			wantDetail: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			client := New(Config{BaseURL: srv.URL})

			err := client.Post(context.Background(), "/test", map[string]string{}, nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *APIError, got %T: %v", err, err)
			}

			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("status code: want %d, got %d", tt.statusCode, apiErr.StatusCode)
			}
			if apiErr.Detail != tt.wantDetail {
				t.Errorf("detail: want %q, got %q", tt.wantDetail, apiErr.Detail)
			}
		})
	}
}

func TestUserAgentHeader(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{
		BaseURL:   srv.URL,
		UserAgent: "bamf-agent/1.0",
	})

	_ = client.Post(context.Background(), "/test", map[string]string{}, nil)
	if gotUA != "bamf-agent/1.0" {
		t.Errorf("User-Agent: want %q, got %q", "bamf-agent/1.0", gotUA)
	}
}

func TestClientCertHeader(t *testing.T) {
	var gotCert string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCert = r.Header.Get("X-Bamf-Client-Cert")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})
	client.SetClientCert([]byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"))

	_ = client.Get(context.Background(), "/test", nil)
	if gotCert == "" {
		t.Error("expected X-Bamf-Client-Cert header, got empty")
	}
}

func TestNoCertHeader_WhenNotSet(t *testing.T) {
	var gotCert string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCert = r.Header.Get("X-Bamf-Client-Cert")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	_ = client.Get(context.Background(), "/test", nil)
	if gotCert != "" {
		t.Errorf("expected no X-Bamf-Client-Cert header, got %q", gotCert)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{
		BaseURL: srv.URL,
		Timeout: 50 * time.Millisecond,
	})

	err := client.Get(context.Background(), "/slow", nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := client.Get(ctx, "/test", nil)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

func TestAPIError_IsNotFound(t *testing.T) {
	err := &APIError{StatusCode: 404, Status: "404 Not Found", Detail: "not found"}
	if !err.IsNotFound() {
		t.Error("expected IsNotFound() to be true")
	}
	if err.IsUnauthorized() {
		t.Error("expected IsUnauthorized() to be false")
	}
}

func TestAPIError_IsUnauthorized(t *testing.T) {
	err := &APIError{StatusCode: 401, Status: "401 Unauthorized", Detail: "bad token"}
	if !err.IsUnauthorized() {
		t.Error("expected IsUnauthorized() to be true")
	}
	if err.IsNotFound() {
		t.Error("expected IsNotFound() to be false")
	}
}

func TestDelete_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"deleted": true}`)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	var got map[string]bool
	err := client.Delete(context.Background(), "/items/1", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["deleted"] {
		t.Error("expected deleted=true")
	}
}
