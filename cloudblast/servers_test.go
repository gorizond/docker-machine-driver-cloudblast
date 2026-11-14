package cloudblast

import (
	"context"
	"net/http"
	"testing"
)

type captureTransport struct {
	requests []*http.Request
	respond  func(*http.Request) (*http.Response, error)
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, req)
	return c.respond(req)
}

func (c *captureTransport) last(method string) *http.Request {
	for i := len(c.requests) - 1; i >= 0; i-- {
		if c.requests[i].Method == method {
			return c.requests[i]
		}
	}
	return nil
}

func newCaptureClient(rt http.RoundTripper) *Client {
	client := NewClient("http://fake", "fake-token", false)
	client.HTTPClient = &http.Client{Transport: rt}
	return client
}

func TestDeleteServerOmitsKeepIPsWhenFalse(t *testing.T) {
	transport := &captureTransport{respond: func(*http.Request) (*http.Response, error) {
		return jsonResponse(204, ""), nil
	}}
	client := newCaptureClient(transport)

	if err := client.DeleteServer(context.Background(), "u-1", false); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests = %d, want 1 (no GET when keep_ips is false)", len(transport.requests))
	}
	req := transport.last(http.MethodDelete)
	if req == nil {
		t.Fatal("DELETE request missing")
	}
	if req.URL.RawQuery != "" {
		t.Fatalf("DELETE query = %q, want empty", req.URL.RawQuery)
	}
	if _, ok := req.URL.Query()["keep_ips"]; ok {
		t.Fatal("keep_ips must be omitted when false")
	}
}

func TestDeleteServerSendsAddressCSVWhenKeepIPsTrue(t *testing.T) {
	transport := &captureTransport{respond: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && req.URL.Path == "/servers/u-1" {
			return jsonResponse(200, `{"data":{"uuid":"u-1","ip_addresses":[
				{"address":"10.0.0.5","type":"ipv4"},
				{"address":"2001:db8::5","type":"ipv6"},
				{"address":"10.0.0.5","type":"ipv4"}
			]}}`), nil
		}
		return jsonResponse(204, ""), nil
	}}
	client := newCaptureClient(transport)

	if err := client.DeleteServer(context.Background(), "u-1", true); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if transport.last(http.MethodGet) == nil {
		t.Fatal("keep_ips=true must fetch the server first")
	}
	req := transport.last(http.MethodDelete)
	if req == nil {
		t.Fatal("DELETE request missing")
	}
	if got, want := req.URL.Query().Get("keep_ips"), "10.0.0.5,2001:db8::5"; got != want {
		t.Fatalf("keep_ips = %q, want %q", got, want)
	}
}

func TestDeleteServerOmitsKeepIPsWhenServerHasNoAddresses(t *testing.T) {
	transport := &captureTransport{respond: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet {
			return jsonResponse(200, `{"data":{"uuid":"u-1","ip_addresses":[]}}`), nil
		}
		return jsonResponse(204, ""), nil
	}}
	client := newCaptureClient(transport)

	if err := client.DeleteServer(context.Background(), "u-1", true); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if req := transport.last(http.MethodDelete); req == nil || req.URL.RawQuery != "" {
		t.Fatalf("DELETE query must be empty, request = %v", req)
	}
}

func TestDeleteServerKeepIPsAbsentServerIsSuccess(t *testing.T) {
	transport := &captureTransport{respond: func(*http.Request) (*http.Response, error) {
		return jsonResponse(404, `{"error":{"code":"NOT_FOUND","message":"gone"}}`), nil
	}}
	client := newCaptureClient(transport)

	if err := client.DeleteServer(context.Background(), "u-1", true); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if transport.last(http.MethodDelete) != nil {
		t.Fatal("DELETE must not be sent when the server is already gone")
	}
}
