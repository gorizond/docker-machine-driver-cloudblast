package cloudblast

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func gzipB64(t *testing.T, content string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestLoadUserDataGzipB64InstallScript(t *testing.T) {
	installScript := "set -e\nexport CATTLE_TOKEN=abc\n"
	encoded := gzipB64(t, installScript)
	cfg := fmt.Sprintf(`#cloud-config
write_files:
  - path: /usr/local/custom_script/install.sh
    permissions: '0600'
    encoding: gzip+b64
    content: %s
runcmd:
  - sh /usr/local/custom_script/install.sh
`, encoded)

	ud, err := LoadUserData(cfg)
	if err != nil {
		t.Fatalf("LoadUserData: %v", err)
	}
	defer func() { _ = ud.Cleanup() }()

	files, ok := ud.Config["write_files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("write_files = %#v", ud.Config["write_files"])
	}
	entry, ok := files[0].(map[string]any)
	if !ok {
		t.Fatalf("write_files[0] = %#v", files[0])
	}
	if entry["permissions"] != "0600" {
		t.Fatalf("permissions = %#v", entry["permissions"])
	}

	decoded, err := DecodeWriteFileContent(entry["content"].(string), entry["encoding"].(string))
	if err != nil {
		t.Fatalf("DecodeWriteFileContent: %v", err)
	}
	if string(decoded) != installScript {
		t.Fatalf("decoded = %q, want %q", decoded, installScript)
	}
	if strings.HasPrefix(string(decoded), "#!") {
		t.Fatal("Rancher strips the shebang; fixture must not have one")
	}

	info, err := os.Stat(ud.TmpPath)
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("temp file mode = %04o, want 0600", perm)
	}
	if ud.SHA256 == "" {
		t.Fatal("SHA256 must be set")
	}
}

func TestLoadUserDataInlinePathAndAtPath(t *testing.T) {
	content := "#cloud-config\nhostname: cb-test\n"
	path := t.TempDir() + "/user-data.yaml"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	inline, err := LoadUserData(content)
	if err != nil {
		t.Fatalf("inline: %v", err)
	}
	defer func() { _ = inline.Cleanup() }()
	fromPath, err := LoadUserData(path)
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	defer func() { _ = fromPath.Cleanup() }()
	fromAt, err := LoadUserData("@" + path)
	if err != nil {
		t.Fatalf("@path: %v", err)
	}
	defer func() { _ = fromAt.Cleanup() }()

	if inline.SHA256 != fromPath.SHA256 || inline.SHA256 != fromAt.SHA256 {
		t.Fatalf("SHA mismatch: %s / %s / %s", inline.SHA256, fromPath.SHA256, fromAt.SHA256)
	}
	for _, ud := range []*UserData{inline, fromPath, fromAt} {
		if ud.Config["hostname"] != "cb-test" {
			t.Fatalf("hostname = %#v", ud.Config["hostname"])
		}
	}
}

func TestLoadUserDataRejectsDangerousKeys(t *testing.T) {
	keys := []string{"network", "network-config", "disk_setup", "mounts", "fs_setup", "power_state"}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			_, err := LoadUserData("#cloud-config\n" + key + ": {}\n")
			if err == nil {
				t.Fatalf("expected %q to be rejected", key)
			}
			if !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("error = %v, want key and reason", err)
			}
		})
	}
}

func TestLoadUserDataRejectsBadWriteFiles(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "relative path", yaml: "write_files:\n  - path: etc/x\n    content: hi\n", wantErr: "absolute"},
		{name: "source unsupported", yaml: "write_files:\n  - path: /etc/x\n    source: https://x\n", wantErr: "source is not supported"},
		{name: "bad encoding", yaml: "write_files:\n  - path: /etc/x\n    encoding: zstd\n    content: hi\n", wantErr: "unsupported encoding"},
		{name: "bad base64", yaml: "write_files:\n  - path: /etc/x\n    encoding: b64\n    content: '!!!'\n", wantErr: "invalid b64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadUserData("#cloud-config\n" + tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadUserDataRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", "   \n"} {
		if _, err := LoadUserData(value); err == nil {
			t.Fatalf("expected error for %q", value)
		}
	}
}

func TestUserDataHelpers(t *testing.T) {
	withPackages := "#cloud-config\npackages:\n  - curl\n"
	ud, err := LoadUserData(withPackages)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ud.Cleanup() }()
	if !ud.HasPackages() || ud.HasUsers() {
		t.Fatalf("HasPackages=%v HasUsers=%v", ud.HasPackages(), ud.HasUsers())
	}

	withUsers := "#cloud-config\nusers:\n  - name: cb\n    ssh_authorized_keys:\n      - ssh-ed25519 AAAA\n"
	ud2, err := LoadUserData(withUsers)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ud2.Cleanup() }()
	if !ud2.HasUsers() {
		t.Fatal("HasUsers must be true")
	}
}
