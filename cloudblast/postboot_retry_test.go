package cloudblast

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type fakePostBootClient struct {
	runFunc   func(cmd string) (string, error)
	writeFunc func(path string, content []byte, perm os.FileMode) error

	probes      int
	uploads     int
	runs        []string
	lastPath    string
	lastContent string
	lastPerm    os.FileMode
}

func (f *fakePostBootClient) ssh() *SSHClient {
	return &SSHClient{
		runFunc: func(_ context.Context, cmd string) (string, error) {
			f.runs = append(f.runs, cmd)
			if strings.Contains(cmd, "boot-finished") {
				f.probes++
			}
			if f.runFunc != nil {
				return f.runFunc(cmd)
			}
			return "", nil
		},
		writeFunc: func(_ context.Context, path string, content []byte, perm os.FileMode) error {
			f.uploads++
			f.lastPath = path
			f.lastContent = string(content)
			f.lastPerm = perm
			if f.writeFunc != nil {
				return f.writeFunc(path, content, perm)
			}
			return nil
		},
	}
}

func (f *fakePostBootClient) run(cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "boot-finished"):
		return "yes", nil
	case strings.HasPrefix(cmd, "sh "):
		return "ok", nil
	default:
		return "", nil
	}
}

func TestPostBootReconnectsAfterProbeDrop(t *testing.T) {
	d := newPostBootTestDriver(t)
	dropErr := errors.New("ssh: unexpected packet in response to channel open")

	first := &fakePostBootClient{runFunc: func(cmd string) (string, error) {
		if strings.Contains(cmd, "boot-finished") {
			return "", dropErr
		}
		return "", nil
	}}
	second := &fakePostBootClient{}
	second.runFunc = second.run

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	connects := 0
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		connects++
		if connects == 1 {
			return first.ssh(), nil
		}
		return second.ssh(), nil
	}

	if err := d.runPostBootScript(context.Background(), "fake", []byte("echo hi")); err != nil {
		t.Fatalf("runPostBootScript: %v", err)
	}
	if connects != 2 {
		t.Fatalf("connects = %d, want 2", connects)
	}
	if second.uploads != 1 || second.lastContent != "echo hi" || second.lastPerm != 0o600 {
		t.Fatalf("upload = %d/%q/%04o", second.uploads, second.lastContent, second.lastPerm)
	}
}

func TestPostBootReconnectsAfterUploadDrop(t *testing.T) {
	d := newPostBootTestDriver(t)

	first := &fakePostBootClient{}
	first.runFunc = first.run
	first.writeFunc = func(string, []byte, os.FileMode) error { return io.EOF }
	second := &fakePostBootClient{}
	second.runFunc = second.run

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	connects := 0
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		connects++
		if connects == 1 {
			return first.ssh(), nil
		}
		return second.ssh(), nil
	}

	if err := d.runPostBootScript(context.Background(), "fake", []byte("echo hi")); err != nil {
		t.Fatalf("runPostBootScript: %v", err)
	}
	if connects != 2 || first.uploads != 1 || second.uploads != 1 {
		t.Fatalf("connects=%d uploads=%d/%d", connects, first.uploads, second.uploads)
	}
	if second.probes != 0 {
		t.Fatalf("upload retry must not repeat the boot-finished probe (probes=%d)", second.probes)
	}
	if second.lastContent != "echo hi" {
		t.Fatalf("uploaded script = %q", second.lastContent)
	}
}

func TestPostBootReconnectsAndRetriesRunAfterDrop(t *testing.T) {
	d := newPostBootTestDriver(t)

	first := &fakePostBootClient{runFunc: func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "sh ") {
			return "", errors.New("read: connection reset by peer")
		}
		return "yes", nil
	}}
	second := &fakePostBootClient{}
	second.runFunc = second.run

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	connects := 0
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		connects++
		if connects == 1 {
			return first.ssh(), nil
		}
		return second.ssh(), nil
	}

	if err := d.runPostBootScript(context.Background(), "fake", []byte("echo hi")); err != nil {
		t.Fatalf("runPostBootScript: %v", err)
	}
	if connects != 2 || first.uploads != 1 || second.uploads != 0 {
		t.Fatalf("connects=%d uploads=%d/%d, want 2 and 1/0", connects, first.uploads, second.uploads)
	}
	if second.probes != 0 {
		t.Fatalf("run retry must not repeat probe/upload (probes=%d)", second.probes)
	}
	if len(second.runs) == 0 || !strings.HasPrefix(second.runs[0], "sh ") {
		t.Fatalf("second connection did not re-run the script: %v", second.runs)
	}
}

func TestPostBootPersistentDropsTimeout(t *testing.T) {
	d := newPostBootTestDriver(t)
	dropErr := errors.New("ssh: unexpected packet in response to channel open")

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		client := &fakePostBootClient{runFunc: func(cmd string) (string, error) {
			if strings.Contains(cmd, "boot-finished") {
				return "", dropErr
			}
			return "", nil
		}}
		return client.ssh(), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err := d.runPostBootScript(ctx, "fake", []byte("echo hi"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "did not finish within") ||
		!strings.Contains(err.Error(), "step=boot-finished") ||
		!strings.Contains(err.Error(), "attempts=") {
		t.Fatalf("error = %v, want timeout with step and drops", err)
	}
}

func newPostBootTestDriver(t *testing.T) *Driver {
	t.Helper()
	d := NewDriver("machine-1", t.TempDir())
	d.pollInterval = time.Millisecond
	return d
}
