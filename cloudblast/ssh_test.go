package cloudblast

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	machinessh "github.com/docker/machine/libmachine/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

func testPrivateKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_rsa")
	if err := machinessh.GenerateSSHKey(path); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return path
}

func TestWaitForSSHRetriesAuthFailureUntilTimeout(t *testing.T) {
	keyPath := testPrivateKey(t)
	restore := dialSSHFunc
	defer func() { dialSSHFunc = restore }()

	authErr := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	attempts := 0
	dialSSHFunc = func(context.Context, string, *cryptossh.ClientConfig) (*cryptossh.Client, error) {
		attempts++
		return nil, authErr
	}

	start := time.Now()
	_, err := WaitForSSH(context.Background(), SSHConfig{
		Host:           "127.0.0.1",
		Port:           22,
		User:           "root",
		PrivateKeyPath: keyPath,
		Timeout:        200 * time.Millisecond,
		RetryInterval:  5 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("error = %v, want timeout wrapping the auth error", err)
	}
	if attempts < 2 {
		t.Fatalf("auth failure was not retried: attempts=%d", attempts)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("returned before the timeout: %s", elapsed)
	}
	if reason := sshFailureReason(authErr); !strings.Contains(reason, "authentication not ready") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestWaitForSSHMissingKeyFileIsFatal(t *testing.T) {
	restore := dialSSHFunc
	defer func() { dialSSHFunc = restore }()
	dialCalls := 0
	dialSSHFunc = func(context.Context, string, *cryptossh.ClientConfig) (*cryptossh.Client, error) {
		dialCalls++
		return nil, errors.New("must not dial")
	}

	_, err := WaitForSSH(context.Background(), SSHConfig{
		Host:           "127.0.0.1",
		PrivateKeyPath: filepath.Join(t.TempDir(), "missing"),
		Timeout:        time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "read private key") {
		t.Fatalf("error = %v, want read-private-key error", err)
	}
	if dialCalls != 0 {
		t.Fatalf("dial was attempted %d times for a missing key", dialCalls)
	}
}

func TestWaitForSSHMalformedKeyFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := dialSSHFunc
	defer func() { dialSSHFunc = restore }()
	dialCalls := 0
	dialSSHFunc = func(context.Context, string, *cryptossh.ClientConfig) (*cryptossh.Client, error) {
		dialCalls++
		return nil, errors.New("must not dial")
	}

	_, err := WaitForSSH(context.Background(), SSHConfig{
		Host:           "127.0.0.1",
		PrivateKeyPath: path,
		Timeout:        time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "parse private key") {
		t.Fatalf("error = %v, want parse-private-key error", err)
	}
	if dialCalls != 0 {
		t.Fatalf("dial was attempted %d times for a malformed key", dialCalls)
	}
}
