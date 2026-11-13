package cloudblast

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeRunner struct {
	commands   []string
	failModule string
	failSecret string
	files      map[string][]byte
}

func (f *fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.commands = append(f.commands, cmd)
	if f.failModule != "" && strings.Contains(cmd, "--name "+f.failModule) {
		if f.failSecret != "" {
			return "", errors.New("command failed with CATTLE_TOKEN=" + f.failSecret)
		}
		return "", errors.New("command failed")
	}
	return "", nil
}

func (f *fakeRunner) WriteFile(_ context.Context, path string, content []byte, _ os.FileMode) error {
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[path] = content
	return nil
}

func userDataTempFile(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/user-data.yaml"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyCloudConfigOrderAndRestore(t *testing.T) {
	path := userDataTempFile(t, "#cloud-config\nhostname: cb-x\n")
	runner := &fakeRunner{}
	modules := []string{"cc_bootcmd", "cc_write_files", "cc_set_hostname", "cc_runcmd", "cc_scripts_user"}

	applied, err := ApplyCloudConfig(context.Background(), runner, path, modules)
	if err != nil {
		t.Fatalf("ApplyCloudConfig: %v", err)
	}
	if strings.Join(applied, ",") != strings.Join(modules, ",") {
		t.Fatalf("applied = %v, want %v", applied, modules)
	}
	if len(runner.commands) != len(modules)+2 {
		t.Fatalf("commands = %d, want %d: %v", len(runner.commands), len(modules)+2, runner.commands)
	}
	if !strings.HasPrefix(runner.commands[0], "cp -a '/var/lib/cloud/instance/cloud-config.txt'") {
		t.Fatalf("first command must be the backup, got %q", runner.commands[0])
	}
	if !strings.Contains(runner.commands[len(runner.commands)-1], "cloudblast-backup") {
		t.Fatalf("last command must restore the backup, got %q", runner.commands[len(runner.commands)-1])
	}
	if _, ok := runner.files[instanceCloudConfig]; !ok {
		t.Fatal("merged cloud-config was not written")
	}
	for _, cmd := range runner.commands {
		if strings.Contains(cmd, "cloud-init clean") || strings.Contains(cmd, "cloud-init init") {
			t.Fatalf("forbidden command issued: %q", cmd)
		}
	}
}

func TestApplyCloudConfigFailureRestoresAndMasks(t *testing.T) {
	path := userDataTempFile(t, "#cloud-config\nruncmd: [echo hi]\n")
	runner := &fakeRunner{failModule: "cc_runcmd", failSecret: "s3cr3t-token-value"}

	applied, err := ApplyCloudConfig(context.Background(), runner, path, []string{"cc_bootcmd", "cc_runcmd", "cc_scripts_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Join(applied, ",") != "cc_bootcmd" {
		t.Fatalf("applied = %v", applied)
	}
	if !strings.Contains(err.Error(), "cc_runcmd") {
		t.Fatalf("error = %v, want module name", err)
	}
	if strings.Contains(err.Error(), "s3cr3t-token-value") {
		t.Fatalf("secret leaked into error: %v", err)
	}
	if !strings.Contains(runner.commands[len(runner.commands)-1], "cloudblast-backup") {
		t.Fatal("backup was not restored after a failed module")
	}
	if strings.Contains(strings.Join(runner.commands, " "), "cc_scripts_user") {
		t.Fatal("modules after the failed one must not run")
	}
}

func TestCloudInitModulesConditionals(t *testing.T) {
	plain, err := LoadUserData("#cloud-config\nhostname: cb-x\n")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Cleanup() }()
	if got := strings.Join(CloudInitModules(plain), ","); got != "cc_bootcmd,cc_write_files,cc_set_hostname,cc_write_files_deferred,cc_runcmd,cc_scripts_user" {
		t.Fatalf("plain modules = %s", got)
	}

	full, err := LoadUserData("#cloud-config\npackages: [curl]\nusers:\n  - name: cb\n")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = full.Cleanup() }()
	if got := strings.Join(CloudInitModules(full), ","); got != "cc_bootcmd,cc_write_files,cc_set_hostname,cc_package_update_upgrade_install,cc_write_files_deferred,cc_users_groups,cc_runcmd,cc_scripts_user" {
		t.Fatalf("full modules = %s", got)
	}
}
