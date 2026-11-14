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
	if got, want := fake.writes[hostnameUnitPath], hostnameUnitContent("cb-live-node"); got != want {
		t.Fatalf("unit content = %q, want %q", got, want)
	}
	if fake.perms[hostnameUnitPath] != 0o644 {
		t.Fatalf("unit mode = %04o", fake.perms[hostnameUnitPath])
	}
	if len(fake.runs) != 2 || fake.runs[0] != "hostnamectl set-hostname 'cb-live-node'" || fake.runs[1] != hostnameUnitEnableCmd {
		t.Fatalf("commands = %v", fake.runs)
	}

	// Idempotent: a second apply rewrites the same content.
	if err := d.applyHostname(context.Background(), client, "cb-live-node"); err != nil {
		t.Fatalf("second applyHostname: %v", err)
	}
	if fake.writes[preserveHostnamePath] != preserveHostnameConfig || len(fake.runs) != 4 {
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
	want := []string{
		"hostnamectl set-hostname 'cb-live-node'",
		"hostname 'cb-live-node'",
		hostnameUnitEnableCmd,
	}
	if len(runs) != len(want) {
		t.Fatalf("commands = %v, want %v", runs, want)
	}
	for i := range want {
		if runs[i] != want[i] {
			t.Fatalf("commands = %v, want %v", runs, want)
		}
	}
}

func TestHostnameUnitContent(t *testing.T) {
	content := hostnameUnitContent("cb-live-node")
	wants := []string{
		"[Unit]",
		"Description=CloudBlast persistent hostname",
		"After=cloud-init.target network-online.target",
		"Wants=network-online.target",
		"[Service]",
		"Type=oneshot",
		`ExecStart=/bin/sh -c 'hostnamectl set-hostname cb-live-node 2>/dev/null || hostname cb-live-node; printf "%s\n" cb-live-node > /etc/hostname'`,
		"RemainAfterExit=yes",
		"[Install]",
		"WantedBy=multi-user.target",
	}
	for _, want := range wants {
		if !strings.Contains(content, want) {
			t.Fatalf("unit content missing %q:\n%s", want, content)
		}
	}
	if got := strings.Count(content, "cb-live-node"); got != 3 {
		t.Fatalf("hostname occurrences = %d, want 3", got)
	}
	if strings.Contains(content, "%!s") {
		t.Fatalf("unit content has a formatting error:\n%s", content)
	}
}

func TestHostnameUnitRejectsInjection(t *testing.T) {
	bad := []string{
		"evil'; touch /tmp/pwned; '",
		"two words",
		"line\nbreak",
		strings.Repeat("a", 65),
		"-leading-hyphen",
		"trailing-hyphen-",
		"double..dot",
	}
	for _, name := range bad {
		if isValidHostname(name) {
			t.Fatalf("invalid hostname %q accepted", name)
		}
		if err := NewDriver("m", "").persistHostname(context.Background(), nil, SSHConfig{}, name); err == nil {
			t.Fatalf("persistHostname accepted %q", name)
		}
	}
	for _, name := range []string{"cb-live-node", "a", "cb-live-node.example.com"} {
		if !isValidHostname(name) {
			t.Fatalf("valid hostname %q rejected", name)
		}
	}
}

func TestApplyHostnameSystemdUnavailableDoesNotFail(t *testing.T) {
	d := NewDriver("machine-1", "")
	writes := map[string]string{}
	client := &SSHClient{
		writeFunc: func(_ context.Context, path string, content []byte, _ os.FileMode) error {
			writes[path] = string(content)
			return nil
		},
		runFunc: func(_ context.Context, cmd string) (string, error) {
			if strings.HasPrefix(cmd, "systemctl") {
				return "", errors.New("System has not been booted with systemd as init system")
			}
			return "", nil
		},
	}

	if err := d.applyHostname(context.Background(), client, "cb-live-node"); err != nil {
		t.Fatalf("systemd absence must not fail: %v", err)
	}
	if _, ok := writes[hostnameUnitPath]; !ok {
		t.Fatal("unit must still be written before systemd is attempted")
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
