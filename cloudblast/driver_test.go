package cloudblast

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTransport struct {
	mu    sync.Mutex
	calls []string
	route func(method, path string) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.Method+" "+req.URL.Path)
	f.mu.Unlock()
	return f.route(req.Method, req.URL.Path)
}

func (f *fakeTransport) called(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newUS1Driver(t *testing.T, transport http.RoundTripper) *Driver {
	t.Helper()
	d := NewDriver("cb-test", t.TempDir())
	d.Token = "fake-api-token"
	d.APIBaseURL = "http://fake"
	d.LocationID = 5
	d.PlanID = 19
	d.TemplateSlug = "ubuntu-24.04"
	d.WaitTimeoutSecs = 60
	d.UserDataFlag = "#cloud-config\nhostname: cb-test\n"
	d.pollInterval = time.Millisecond
	d.httpClient = &http.Client{Transport: transport}
	return d
}

func TestCreateInvalidTokenFailsWithoutServerPost(t *testing.T) {
	transport := &fakeTransport{route: func(_, _ string) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, `{"error":{"code":"UNAUTHENTICATED","message":"bad token"}}`), nil
	}}
	d := newUS1Driver(t, transport)

	err := d.Create()
	if err == nil || !strings.Contains(err.Error(), "невалидный API-токен") {
		t.Fatalf("Create error = %v, want invalid-token message", err)
	}
	if transport.called("POST /servers") {
		t.Fatal("server must not be created with an invalid token")
	}
	if d.VMUUID != "" {
		t.Fatalf("VMUUID = %q, want empty", d.VMUUID)
	}
}

func TestCreateMissingIPv4FailsAndCompensates(t *testing.T) {
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "GET /ssh-keys":
			return jsonResponse(200, `{"data":[]}`), nil
		case "POST /ssh-keys":
			return jsonResponse(201, `{"data":{"id":7,"fingerprint":"SHA256:test"}}`), nil
		case "POST /servers":
			return jsonResponse(201, `{"data":{"uuid":"u-1","hostname":"cb-cb-test","status":"installing"}}`), nil
		case "GET /servers/u-1/status":
			return jsonResponse(200, `{"data":{"state":"running","server_status":null}}`), nil
		case "GET /servers/u-1/credentials":
			return jsonResponse(200, `{"data":{"username":"root","password_status":"ready","ipv4":"","ipv6":"2001:db8::1"}}`), nil
		case "DELETE /servers/u-1":
			return jsonResponse(204, ""), nil
		case "GET /servers":
			return jsonResponse(200, `{"data":[]}`), nil
		case "DELETE /ssh-keys/7":
			return jsonResponse(204, ""), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)

	err := d.Create()
	if err == nil || !strings.Contains(err.Error(), "IPv6-only is not supported") {
		t.Fatalf("Create error = %v, want IPv6-only message", err)
	}
	if !transport.called("DELETE /servers/u-1") {
		t.Fatal("half-created server must be deleted")
	}
	if !transport.called("DELETE /ssh-keys/7") {
		t.Fatal("unused SSH key must be deleted")
	}
	if d.VMUUID != "" {
		t.Fatalf("VMUUID = %q, want empty after compensation", d.VMUUID)
	}
}

func TestCreateReconcileAdoptsAfterTimeout(t *testing.T) {
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "POST /servers":
			return nil, errors.New("dial tcp: i/o timeout")
		case "GET /servers":
			return jsonResponse(200, `{"data":[{"uuid":"u-adopt","hostname":"cb-cb-test","status":"installing"}]}`), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)
	api := d.newClient()
	request := CreateServerRequest{
		PlanID: d.PlanID, LocationID: d.LocationID, TemplateSlug: d.TemplateSlug,
		Hostname: d.Hostname(), SSHKeyIDs: []int{1},
	}

	server, err := d.createOrAdopt(context.Background(), api, request, request.Hostname)
	if err != nil {
		t.Fatalf("createOrAdopt: %v", err)
	}
	if server.UUID != "u-adopt" {
		t.Fatalf("adopted uuid = %q, want u-adopt", server.UUID)
	}
}

func TestCreateReconcileRejectsDuplicateHostnames(t *testing.T) {
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "POST /servers":
			return nil, errors.New("timeout")
		case "GET /servers":
			return jsonResponse(200, `{"data":[
				{"uuid":"u-1","hostname":"cb-cb-test"},
				{"uuid":"u-2","hostname":"cb-cb-test"}
			]}`), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)
	request := CreateServerRequest{
		PlanID: d.PlanID, LocationID: d.LocationID, TemplateSlug: d.TemplateSlug,
		Hostname: d.Hostname(), SSHKeyIDs: []int{1},
	}

	server, err := d.createOrAdopt(context.Background(), d.newClient(), request, request.Hostname)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("error = %v, want duplicate-hostname error", err)
	}
	if server != nil {
		t.Fatalf("server = %v, want nil", server)
	}
	if transport.called("DELETE /servers/u-1") || transport.called("DELETE /servers/u-2") {
		t.Fatal("duplicate matches must not trigger deletion")
	}
}

func TestCreateReconcileRetriesOnceWhenNoServerFound(t *testing.T) {
	var posts int
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "POST /servers":
			posts++
			if posts == 1 {
				return nil, errors.New("timeout")
			}
			return jsonResponse(201, `{"data":{"uuid":"u-new","hostname":"cb-cb-test"}}`), nil
		case "GET /servers":
			return jsonResponse(200, `{"data":[]}`), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)
	request := CreateServerRequest{
		PlanID: d.PlanID, LocationID: d.LocationID, TemplateSlug: d.TemplateSlug,
		Hostname: d.Hostname(), SSHKeyIDs: []int{1},
	}

	server, err := d.createOrAdopt(context.Background(), d.newClient(), request, request.Hostname)
	if err != nil {
		t.Fatalf("createOrAdopt: %v", err)
	}
	if server.UUID != "u-new" || posts != 2 {
		t.Fatalf("uuid=%q posts=%d, want u-new/2", server.UUID, posts)
	}
}

func TestWaitServerReadyFailsFastOnInstallFailed(t *testing.T) {
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		if method+" "+path == "GET /servers/u-bad/status" {
			return jsonResponse(200, `{"data":{"state":"running","server_status":"install_failed"}}`), nil
		}
		return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
	}}
	d := newUS1Driver(t, transport)
	api := d.newClient()

	start := time.Now()
	_, err := d.waitServerReady(context.Background(), api, "u-bad")
	if err == nil || !strings.Contains(err.Error(), "install_failed") {
		t.Fatalf("error = %v, want install_failed", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("install_failed must fail fast, took %s", elapsed)
	}
}

func TestProvisioningTimeouts(t *testing.T) {
	d := NewDriver("m", "")
	if got := d.cloudInitTimeout(); got != 15*time.Minute {
		t.Fatalf("default cloud-init timeout = %s, want 15m", got)
	}
	if got := d.sshWaitTimeout(); got != 10*time.Minute {
		t.Fatalf("default SSH timeout = %s, want 10m", got)
	}
	d.WaitTimeoutSecs = 1200
	if got := d.cloudInitTimeout(); got != 20*time.Minute {
		t.Fatalf("cloud-init timeout with 1200s = %s, want 20m", got)
	}
	if got := d.sshWaitTimeout(); got != 20*time.Minute {
		t.Fatalf("SSH timeout with 1200s = %s, want 20m", got)
	}
}

func TestHostnameTruncationIsDeterministic(t *testing.T) {
	longName := strings.Repeat("a", 300)
	d := NewDriver(longName, "")
	first := d.Hostname()
	second := d.Hostname()
	if len(first) != maxHostnameLen {
		t.Fatalf("hostname length = %d, want %d", len(first), maxHostnameLen)
	}
	if first != second {
		t.Fatal("hostname must be deterministic")
	}
	other := NewDriver(longName+"b", "").Hostname()
	if first[:maxHostnameLen-7] != other[:maxHostnameLen-7] {
		t.Fatal("shared prefix expected before the hash suffix")
	}
	if first == other {
		t.Fatal("different names must produce different hashes")
	}
	if got := sshKeyName(longName); len(got) > maxSSHKeyNameLen {
		t.Fatalf("ssh key name length = %d", len(got))
	}
}
