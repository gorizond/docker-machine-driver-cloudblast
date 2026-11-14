package cloudblast

import (
	"net/http"
	"sync/atomic"
	"testing"
)

func TestRemoveKeepsKeyUsedByAnotherServer(t *testing.T) {
	var getServerCalls atomic.Int32
	var keyDeleted atomic.Bool
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "DELETE /servers/u-1":
			return jsonResponse(204, ""), nil
		case "GET /servers/u-1":
			if getServerCalls.Add(1) == 1 {
				return jsonResponse(200, `{"data":{"uuid":"u-1","status":"deleting"}}`), nil
			}
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"gone"}}`), nil
		case "GET /servers":
			return jsonResponse(200, `{"data":[{"uuid":"u-2","ssh_key_ids":[7]}]}`), nil
		case "DELETE /ssh-keys/7":
			keyDeleted.Store(true)
			return jsonResponse(204, ""), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)
	d.VMUUID = "u-1"
	d.SSHKeyID = 7

	if err := d.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if keyDeleted.Load() {
		t.Fatal("key used by another server must be kept")
	}
	if d.VMUUID != "" {
		t.Fatalf("VMUUID = %q, want empty", d.VMUUID)
	}
}

func TestRemoveAlreadyAbsentDeletesUnusedKey(t *testing.T) {
	var keyDeleted atomic.Bool
	transport := &fakeTransport{route: func(method, path string) (*http.Response, error) {
		switch method + " " + path {
		case "DELETE /servers/u-1":
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"gone"}}`), nil
		case "GET /servers/u-1":
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"gone"}}`), nil
		case "GET /servers":
			return jsonResponse(200, `{"data":[]}`), nil
		case "DELETE /ssh-keys/7":
			keyDeleted.Store(true)
			return jsonResponse(204, ""), nil
		default:
			return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"unexpected"}}`), nil
		}
	}}
	d := newUS1Driver(t, transport)
	d.VMUUID = "u-1"
	d.SSHKeyID = 7

	if err := d.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !keyDeleted.Load() {
		t.Fatal("unused key must be deleted")
	}
	if d.VMUUID != "" || d.SSHKeyID != 0 {
		t.Fatalf("state not cleared: uuid=%q key=%d", d.VMUUID, d.SSHKeyID)
	}
}
