package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestAPIError_IsRateLimited(t *testing.T) {
	err := &APIError{StatusCode: 429, Status: "429 Too Many Requests"}
	if !err.IsRateLimited() {
		t.Error("expected IsRateLimited() to be true for 429")
	}
	if err.IsNotFound() {
		t.Error("expected IsNotFound() to be false for 429")
	}

	err404 := &APIError{StatusCode: 404}
	if err404.IsRateLimited() {
		t.Error("expected IsRateLimited() to be false for 404")
	}
}

func TestAPIError_RetryAfterParsing(t *testing.T) {
	// Test parseErrorResponse directly to avoid triggering the retry loop.
	tests := []struct {
		name           string
		statusCode     int
		retryAfter     string
		body           string
		wantRetryAfter time.Duration
		wantDetail     string
	}{
		{
			name:           "429 with Retry-After seconds",
			statusCode:     429,
			retryAfter:     "5",
			body:           `{"detail": "rate limited"}`,
			wantRetryAfter: 5 * time.Second,
			wantDetail:     "rate limited",
		},
		{
			name:           "429 without Retry-After",
			statusCode:     429,
			retryAfter:     "",
			body:           `{"detail": "too many requests"}`,
			wantRetryAfter: 0,
			wantDetail:     "too many requests",
		},
		{
			name:           "429 with non-numeric Retry-After",
			statusCode:     429,
			retryAfter:     "not-a-number",
			body:           "",
			wantRetryAfter: 0,
		},
		{
			name:           "429 with zero Retry-After",
			statusCode:     429,
			retryAfter:     "0",
			body:           "",
			wantRetryAfter: 0,
		},
		{
			name:           "500 with Retry-After ignored",
			statusCode:     500,
			retryAfter:     "5",
			body:           `{"detail": "internal error"}`,
			wantRetryAfter: 0,
			wantDetail:     "internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if tt.retryAfter != "" {
				rec.Header().Set("Retry-After", tt.retryAfter)
			}
			rec.WriteHeader(tt.statusCode)
			if tt.body != "" {
				io.WriteString(rec, tt.body)
			}

			apiErr := parseErrorResponse(rec.Result())
			if apiErr.RetryAfter != tt.wantRetryAfter {
				t.Errorf("RetryAfter: want %v, got %v", tt.wantRetryAfter, apiErr.RetryAfter)
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("StatusCode: want %d, got %d", tt.statusCode, apiErr.StatusCode)
			}
			if tt.wantDetail != "" && apiErr.Detail != tt.wantDetail {
				t.Errorf("Detail: want %q, got %q", tt.wantDetail, apiErr.Detail)
			}
		})
	}
}

func TestRetry429_ThenSuccess(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"detail": "rate limited"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status": "ok"}`)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	var got map[string]string
	err := client.Get(context.Background(), "/test", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("unexpected response: %+v", got)
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}
}

func TestRetry429_PostBodyResent(t *testing.T) {
	var attempts atomic.Int32
	var lastBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody = string(body)
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	err := client.Post(context.Background(), "/test", map[string]string{"key": "value"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}

	// Verify the body was re-sent correctly on retry
	var parsed map[string]string
	if err := json.Unmarshal([]byte(lastBody), &parsed); err != nil {
		t.Fatalf("failed to parse body from retry: %v", err)
	}
	if parsed["key"] != "value" {
		t.Errorf("expected key=value in retried body, got %v", parsed)
	}
}

func TestRetry429_ExhaustedReturnsError(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"detail": "rate limited"}`)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	// Use a context with deadline to keep the test from waiting 7+ seconds.
	// The context should be long enough for at least some retries but will
	// cancel before all 3 retries complete their delay.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	err := client.Get(ctx, "/test", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should have made at least 2 attempts (initial + 1 retry within 2.5s)
	got := attempts.Load()
	if got < 2 {
		t.Errorf("expected at least 2 attempts, got %d", got)
	}
}

func TestRetry429_ContextCancelledDuringWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Get(ctx, "/test", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
	// Should return quickly (context timeout), not wait the full 60s Retry-After
	if elapsed > 1*time.Second {
		t.Errorf("expected fast return on context cancel, took %v", elapsed)
	}
}

func TestRetry429_NonRetryableErrorNotRetried(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"detail": "internal error"}`)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	err := client.Get(context.Background(), "/test", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected 500, got %d", apiErr.StatusCode)
	}
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (no retry for 500), got %d", attempts.Load())
	}
}

func TestRetry429_GetNoBody(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok": true}`)
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL})

	var got map[string]bool
	err := client.Get(context.Background(), "/test", &got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["ok"] {
		t.Error("expected ok=true")
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}
}
