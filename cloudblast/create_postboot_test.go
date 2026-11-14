package cloudblast

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
)

// readyAPI is the minimal route table for a server that becomes ready with IPv4.
func readyAPI(method, path string) (*http.Response, error) {
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
		return jsonResponse(200, `{"data":{"username":"root","password_status":"ready","ipv4":"203.0.113.5"}}`), nil
	default:
		return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
	}
}

func TestCreateWithoutPostBootScriptSkipsSSH(t *testing.T) {
	transport := &fakeTransport{route: readyAPI}
	d := newUS1Driver(t, transport)
	d.WaitBootFinished = false

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		t.Fatal("SSH must not be used when no post-boot script is configured")
		return nil, nil
	}

	if err := d.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.BaseDriver.IPAddress != "203.0.113.5" {
		t.Fatalf("IPAddress = %q", d.BaseDriver.IPAddress)
	}
}

func TestCreateEmptyPostBootScriptIsNoOp(t *testing.T) {
	transport := &fakeTransport{route: readyAPI}
	d := newUS1Driver(t, transport)
	d.WaitBootFinished = false
	d.PostBootScript = "   "

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		t.Fatal("empty post-boot script must not open SSH")
		return nil, nil
	}

	if err := d.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestCreatePostBootScriptFailureCompensates(t *testing.T) {
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "DELETE /servers/u-1":
			return jsonResponse(204, ""), nil
		case "GET /servers":
			return jsonResponse(200, `{"data":[]}`), nil
		case "DELETE /ssh-keys/7":
			return jsonResponse(204, ""), nil
		default:
			return readyAPI(method, path)
		}
	}}
	d := newUS1Driver(t, transport)
	d.WaitBootFinished = false
	d.PostBootScript = "exit 7"

	uploads := map[string]string{}
	perms := map[string]os.FileMode{}
	fake := &SSHClient{
		runFunc: func(_ context.Context, cmd string) (string, error) {
			switch {
			case strings.Contains(cmd, "boot-finished"):
				return "yes", nil
			case strings.HasPrefix(cmd, "sh ") && strings.Contains(cmd, "cloudblast-post-boot.sh"):
				return "boom", errors.New("exit status 7")
			default:
				return "", nil
			}
		},
		writeFunc: func(_ context.Context, path string, content []byte, perm os.FileMode) error {
			uploads[path] = string(content)
			perms[path] = perm
			return nil
		},
	}
	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) { return fake, nil }

	err := d.Create()
	if err == nil || !strings.Contains(err.Error(), "post-boot script failed") {
		t.Fatalf("Create error = %v, want post-boot failure", err)
	}
	if got := uploads[postBootScriptPath]; got != "exit 7" {
		t.Fatalf("uploaded script = %q", got)
	}
	if perms[postBootScriptPath] != 0o600 {
		t.Fatalf("uploaded script mode = %04o", perms[postBootScriptPath])
	}
	if !transport.called("DELETE /servers/u-1") {
		t.Fatal("script failure must trigger compensating delete")
	}
	if d.VMUUID != "" {
		t.Fatalf("VMUUID = %q, want empty", d.VMUUID)
	}
}
