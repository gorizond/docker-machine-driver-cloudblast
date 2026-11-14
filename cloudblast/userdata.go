package cloudblast

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// rejectedKeys would be dangerous to apply to an already running node.
var rejectedKeys = map[string]string{
	"network":        "re-applying network configuration over SSH would break connectivity",
	"network-config": "re-applying network configuration over SSH would break connectivity",
	"disk_setup":     "disk configuration is not applied to a running node",
	"mounts":         "mount configuration is not applied to a running node",
	"fs_setup":       "filesystem configuration is not applied to a running node",
	"power_state":    "power state changes are not applied post-boot",
}

// UserData is a validated cloud-config. Only the SHA256 digest and the path to a
// 0600 temporary file are meant to be persisted; Config/Raw stay in memory.
type UserData struct {
	SHA256  string
	TmpPath string
	Config  map[string]any
	Raw     []byte
}

// LoadUserData reads cloud-config from a file path, an @path reference or an
// inline value, validates the supported subset and writes a 0600 temp copy.
// The caller must call Cleanup when done (Create or PreCreateCheck).
func LoadUserData(value string) (*UserData, error) {
	raw, err := readUserData(value)
	if err != nil {
		return nil, err
	}
	cfg, err := parseCloudConfig(raw)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(raw)
	tmp, err := os.CreateTemp("", "cloudblast-user-data-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("cloudblast-user-data: create temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("cloudblast-user-data: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("cloudblast-user-data: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("cloudblast-user-data: close temp file: %w", err)
	}

	return &UserData{
		SHA256:  hex.EncodeToString(sum[:]),
		TmpPath: tmp.Name(),
		Config:  cfg,
		Raw:     raw,
	}, nil
}

// Cleanup removes the temporary user-data file. Safe on nil and repeated calls.
func (u *UserData) Cleanup() error {
	if u == nil || u.TmpPath == "" {
		return nil
	}
	err := os.Remove(u.TmpPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	u.TmpPath = ""
	return err
}

// HasPackages reports whether the config installs packages.
func (u *UserData) HasPackages() bool {
	if u == nil {
		return false
	}
	list, ok := u.Config["packages"].([]any)
	return ok && len(list) > 0
}

// Hostname returns the desired hostname from the merged cloud-config, if any.
func (u *UserData) Hostname() string {
	if u == nil {
		return ""
	}
	value, ok := u.Config["hostname"].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// HasUsers reports whether the config creates users or injects authorized keys.
func (u *UserData) HasUsers() bool {
	if u == nil {
		return false
	}
	if list, ok := u.Config["users"].([]any); ok && len(list) > 0 {
		return true
	}
	if list, ok := u.Config["ssh_authorized_keys"].([]any); ok && len(list) > 0 {
		return true
	}
	return false
}

func readUserData(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("cloudblast-user-data is required")
	}
	if strings.HasPrefix(value, "@") {
		return readUserDataFile(strings.TrimPrefix(value, "@"))
	}
	if !strings.Contains(value, "\n") {
		if info, err := os.Stat(value); err == nil && !info.IsDir() {
			return readUserDataFile(value)
		}
	}
	return []byte(value), nil
}

func readUserDataFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cloudblast-user-data: read %q: %w", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("cloudblast-user-data: file %q is empty", path)
	}
	return raw, nil
}

func parseCloudConfig(raw []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("cloudblast-user-data: cloud-config is empty")
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("cloudblast-user-data: invalid YAML: %w", err)
	}
	if len(cfg) == 0 {
		return nil, errors.New("cloudblast-user-data: cloud-config has no keys")
	}
	if err := validateCloudConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
