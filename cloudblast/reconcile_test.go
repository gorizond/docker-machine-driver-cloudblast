package cloudblast

import (
	"strings"
	"testing"
)

func TestSelectServerByHostname(t *testing.T) {
	servers := []Server{
		{UUID: "a", Hostname: "cb-one"},
		{UUID: "b", Hostname: "cb-two"},
		{UUID: "c", Hostname: "cb-two"},
	}

	t.Run("no match means create", func(t *testing.T) {
		server, create, err := SelectServerByHostname(servers, "cb-new")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !create || server != nil {
			t.Fatalf("server=%v create=%v, want nil/true", server, create)
		}
	})

	t.Run("one match is adopted", func(t *testing.T) {
		server, create, err := SelectServerByHostname(servers, "cb-one")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if create || server == nil || server.UUID != "a" {
			t.Fatalf("server=%v create=%v, want a/false", server, create)
		}
	})

	t.Run("multiple matches are an error", func(t *testing.T) {
		server, create, err := SelectServerByHostname(servers, "cb-two")
		if err == nil {
			t.Fatal("expected error for duplicate hostnames")
		}
		if server != nil || create {
			t.Fatalf("server=%v create=%v, want nil/false", server, create)
		}
		if !strings.Contains(err.Error(), "cb-two") || !strings.Contains(err.Error(), "2 servers") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("empty hostname is rejected", func(t *testing.T) {
		if _, _, err := SelectServerByHostname(servers, " "); err == nil {
			t.Fatal("expected error")
		}
	})
}
