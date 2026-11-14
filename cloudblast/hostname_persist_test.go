package cloudblast

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeHostnameSSH struct {
	writes map[string]string
	perms  map[string]os.FileMode
	runs   []string
}

func (f *fakeHostnameSSH) client() *SSHClient {
	return &SSHClient{
		runFunc: func(_ context.Context, cmd string) (string, error) {
			f.runs = append(f.runs, cmd)
			return "", nil
		},
		writeFunc: func(_ context.Context, path string, content []byte, perm os.FileMode) error {
			if f.writes == nil {
				f.writes = map[string]string{}
				f.perms = map[string]os.FileMode{}
			}
			f.writes[path] = string(content)
			f.perms[path] = perm
			return nil
		},
	}
}

func loadUserDataForTest(t *testing.T, content string) *UserData {
	t.Helper()
	ud, err := LoadUserData(content)
	if err != nil {
		t.Fatalf("LoadUserData: %v", err)
	}
	t.Cleanup(func() { _ = ud.Cleanup() })
	return ud
}

func TestUserDataHostnameExtraction(t *testing.T) {
	withHostname := loadUserDataForTest(t, "#cloud-config\nhostname: cb-live-node\nruncmd: [echo hi]\n")
	if got := withHostname.Hostname(); got != "cb-live-node" {
		t.Fatalf("hostname = %q, want cb-live-node", got)
	}
	withoutHostname := loadUserDataForTest(t, "#cloud-config\nruncmd: [echo hi]\n")
	if got := withoutHostname.Hostname(); got != "" {
		t.Fatalf("hostname = %q, want empty", got)
	}
}

func TestDesiredHostnameFallback(t *testing.T) {
	d := NewDriver("machine-1", "")
	withHostname := loadUserDataForTest(t, "#cloud-config\nhostname: cb-live-node\n")
	withoutHostname := loadUserDataForTest(t, "#cloud-config\nruncmd: [echo hi]\n")

	if got := d.desiredHostname(withHostname, "cb-provider"); got != "cb-live-node" {
		t.Fatalf("user-data hostname = %q", got)
	}
	if got := d.desiredHostname(withoutHostname, "cb-provider"); got != "machine-1" {
		t.Fatalf("machine-name fallback = %q", got)
	}
	d.MachineName = ""
	if got := d.desiredHostname(withoutHostname, "cb-provider"); got != "cb-provider" {
		t.Fatalf("server-hostname fallback = %q", got)
	}
}

func TestApplyHostnameWritesPreserveConfigAndHostsFile(t *testing.T) {
	d := NewDriver("machine-1", "")
	fake := &fakeHostnameSSH{}
	client := fake.client()

	if err := d.applyHostname(context.Background(), client, "cb-live-node"); err != nil {
		t.Fatalf("applyHostname: %v", err)
	}
	if got := fake.writes[preserveHostnamePath]; got != preserveHostnameConfig {
		t.Fatalf("preserve config = %q, want %q", got, preserveHostnameConfig)
	}
	if fake.perms[preserveHostnamePath] != 0o644 {
		t.Fatalf("preserve config mode = %04o", fake.perms[preserveHostnamePath])
	}
	if got := fake.writes[etcHostnamePath]; got != "cb-live-node\n" {
		t.Fatalf("/etc/hostname = %q", got)
	}
	if fake.perms[etcHostnamePath] != 0o644 {
		t.Fatalf("/etc/hostname mode = %04o", fake.perms[etcHostnamePath])
	}
	if len(fake.runs) != 1 || fake.runs[0] != "hostnamectl set-hostname 'cb-live-node'" {
		t.Fatalf("commands = %v", fake.runs)
	}

	// Idempotent: a second apply rewrites the same content.
	if err := d.applyHostname(context.Background(), client, "cb-live-node"); err != nil {
		t.Fatalf("second applyHostname: %v", err)
	}
	if fake.writes[preserveHostnamePath] != preserveHostnameConfig || len(fake.runs) != 2 {
		t.Fatalf("second apply not idempotent: writes=%v runs=%v", fake.writes, fake.runs)
	}
}

func TestApplyHostnameFallsBackToHostnameCommand(t *testing.T) {
	d := NewDriver("machine-1", "")
	runs := []string{}
	client := &SSHClient{
		writeFunc: func(context.Context, string, []byte, os.FileMode) error { return nil },
		runFunc: func(_ context.Context, cmd string) (string, error) {
			runs = append(runs, cmd)
			if strings.HasPrefix(cmd, "hostnamectl") {
				return "", errors.New("exit status 127")
			}
			return "", nil
		},
	}

	if err := d.applyHostname(context.Background(), client, "cb-live-node"); err != nil {
		t.Fatalf("applyHostname: %v", err)
	}
	if len(runs) != 2 || runs[0] != "hostnamectl set-hostname 'cb-live-node'" || runs[1] != "hostname 'cb-live-node'" {
		t.Fatalf("commands = %v", runs)
	}
}

func TestPersistHostnameSkipsEmpty(t *testing.T) {
	d := NewDriver("machine-1", "")
	fake := &fakeHostnameSSH{}

	if err := d.persistHostname(context.Background(), fake.client(), SSHConfig{}, "  "); err != nil {
		t.Fatalf("persistHostname: %v", err)
	}
	if len(fake.writes) != 0 || len(fake.runs) != 0 {
		t.Fatalf("empty hostname must skip SSH work: writes=%v runs=%v", fake.writes, fake.runs)
	}
}

func TestPersistHostnameRejectsInvalidName(t *testing.T) {
	d := NewDriver("machine-1", "")
	err := d.persistHostname(context.Background(), nil, SSHConfig{}, "bad host\nname")
	if err == nil || !strings.Contains(err.Error(), "not a valid hostname") {
		t.Fatalf("error = %v, want invalid-hostname error", err)
	}
}
