package cloudblast

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, "cb_live_supersecret", false)
	c.MaxAttempts = 3
	c.RetryBackoff = time.Millisecond
	c.sleep = func(time.Duration) {}
	return c, srv
}

func TestClientEnvelopeHeadersAndDecode(t *testing.T) {
	var gotAuth, gotAgent, gotAccept string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"data":{"uuid":"abc-123","hostname":"cb-t"}}`))
	})

	srv, err := c.GetServer(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if srv.UUID != "abc-123" || srv.Hostname != "cb-t" {
		t.Fatalf("unexpected server: %+v", srv)
	}
	if gotAuth != "Bearer cb_live_supersecret" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotAgent != userAgent {
		t.Fatalf("User-Agent = %q", gotAgent)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
}

func TestClientErrorMapping(t *testing.T) {
	cases := []struct {
		status  int
		code    string
		message string
		want    string
	}{
		{401, "UNAUTHENTICATED", "bad token", "невалидный API-токен"},
		{403, "IP_NOT_ALLOWED", "ip denied", "IP не в whitelist"},
		{402, "", "no money", "недостаточно средств"},
		{404, "", "gone", "сервер не найден"},
		{409, "", "busy", "конфликт состояния"},
		{422, "", "validation failed", "ошибка валидации"},
		{429, "", "slow down", "лимит запросов"},
		{500, "", "boom", "временная ошибка"},
		{503, "", "", "временная ошибка"},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				body, _ := json.Marshal(map[string]any{
					"error": map[string]any{"code": tc.code, "message": tc.message, "details": map[string]any{"field": "plan_id"}},
				})
				_, _ = w.Write(body)
			})
			c.MaxAttempts = 1

			_, err := c.GetServer(context.Background(), "x")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "cb_live_supersecret") {
				t.Fatalf("token leaked into error: %q", err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *APIError, got %T", err)
			}
		})
	}
}

func TestClientDoesNotRetryNonIdempotentPost(t *testing.T) {
	var attempts atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.CreateServer(context.Background(), CreateServerRequest{
		PlanID: 19, LocationID: 5, TemplateSlug: "ubuntu-24.04", Hostname: "cb-t", SSHKeyIDs: []int{1},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("POST was attempted %d times, want 1", got)
	}
}

func TestClientRetriesGetOn5xx(t *testing.T) {
	var attempts atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"uuid":"ok"}}`))
	})

	srv, err := c.GetServer(context.Background(), "ok")
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if srv.UUID != "ok" {
		t.Fatalf("uuid = %q", srv.UUID)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestClientHonorsRetryAfterOn429(t *testing.T) {
	var attempts atomic.Int32
	var slept []time.Duration
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"uuid":"ok"}}`))
	})
	c.sleep = func(d time.Duration) { slept = append(slept, d) }

	if _, err := c.GetServer(context.Background(), "ok"); err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if len(slept) != 1 || slept[0] != 7*time.Second {
		t.Fatalf("sleeps = %v, want [7s]", slept)
	}
}

func TestClientNotFoundHelpers(t *testing.T) {
	err := &APIError{StatusCode: http.StatusNotFound}
	if !IsNotFound(err) || IsUnauthorized(err) {
		t.Fatal("IsNotFound/IsUnauthorized mismatch for 404")
	}
	authErr := &APIError{StatusCode: http.StatusUnauthorized}
	if IsNotFound(authErr) || !IsUnauthorized(authErr) {
		t.Fatal("IsNotFound/IsUnauthorized mismatch for 401")
	}
	if IsNotFound(errors.New("other")) {
		t.Fatal("plain error treated as 404")
	}
}

func TestCreateServerRequestValidate(t *testing.T) {
	valid := CreateServerRequest{PlanID: 1, LocationID: 2, TemplateSlug: "ubuntu-24.04", Hostname: "cb-x", SSHKeyIDs: []int{1}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	noKeys := valid
	noKeys.SSHKeyIDs = nil
	if err := noKeys.Validate(); err == nil {
		t.Fatal("expected error for missing ssh keys")
	}
	tooMany := valid
	tooMany.SSHKeyIDs = make([]int, 21)
	if err := tooMany.Validate(); err == nil {
		t.Fatal("expected error for >20 ssh keys")
	}
	longHost := valid
	longHost.Hostname = strings.Repeat("a", 192)
	if err := longHost.Validate(); err == nil {
		t.Fatal("expected error for long hostname")
	}
}
