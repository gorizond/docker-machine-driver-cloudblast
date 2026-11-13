package cloudblast

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var permissionsRE = regexp.MustCompile(`^[0-7]{3,4}$`)

func validateCloudConfig(cfg map[string]any) error {
	for key, reason := range rejectedKeys {
		if _, ok := cfg[key]; ok {
			return fmt.Errorf("cloudblast-user-data: key %q is not supported: %s", key, reason)
		}
	}

	if v, ok := cfg["hostname"]; ok {
		if _, isString := v.(string); !isString {
			return errors.New(`cloudblast-user-data: key "hostname" must be a string`)
		}
	}
	for _, key := range []string{"bootcmd", "runcmd"} {
		if v, ok := cfg[key]; ok {
			if err := validateCommandList(key, v); err != nil {
				return err
			}
		}
	}
	if v, ok := cfg["packages"]; ok {
		if err := validateStringList("packages", v); err != nil {
			return err
		}
	}
	if v, ok := cfg["ssh_authorized_keys"]; ok {
		if err := validateStringList("ssh_authorized_keys", v); err != nil {
			return err
		}
	}
	if v, ok := cfg["users"]; ok {
		if err := validateUsers(v); err != nil {
			return err
		}
	}
	if v, ok := cfg["write_files"]; ok {
		if err := validateWriteFiles(v); err != nil {
			return err
		}
	}
	return nil
}

func validateCommandList(key string, value any) error {
	list, ok := value.([]any)
	if !ok {
		return fmt.Errorf("cloudblast-user-data: key %q must be a list", key)
	}
	for i, item := range list {
		switch item.(type) {
		case string, []any:
		default:
			return fmt.Errorf("cloudblast-user-data: %s[%d] must be a string or a list", key, i)
		}
	}
	return nil
}

func validateStringList(key string, value any) error {
	list, ok := value.([]any)
	if !ok {
		return fmt.Errorf("cloudblast-user-data: key %q must be a list", key)
	}
	for i, item := range list {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("cloudblast-user-data: %s[%d] must be a string", key, i)
		}
	}
	return nil
}

func validateUsers(value any) error {
	list, ok := value.([]any)
	if !ok {
		return errors.New(`cloudblast-user-data: key "users" must be a list`)
	}
	for i, item := range list {
		switch user := item.(type) {
		case string:
			continue
		case map[string]any:
			if keys, ok := user["ssh_authorized_keys"]; ok {
				if err := validateStringList("users.ssh_authorized_keys", keys); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("cloudblast-user-data: users[%d] must be a string or a map", i)
		}
	}
	return nil
}

func validateWriteFiles(value any) error {
	list, ok := value.([]any)
	if !ok {
		return errors.New(`cloudblast-user-data: key "write_files" must be a list`)
	}
	for i, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("cloudblast-user-data: write_files[%d] must be a map", i)
		}
		path, _ := entry["path"].(string)
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("cloudblast-user-data: write_files[%d].path is required", i)
		}
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("cloudblast-user-data: write_files[%d].path %q must be absolute", i, path)
		}
		if _, ok := entry["source"]; ok {
			return fmt.Errorf("cloudblast-user-data: write_files[%d].source is not supported; use content", i)
		}
		content, _ := entry["content"].(string)
		if _, hasContent := entry["content"]; !hasContent {
			return fmt.Errorf("cloudblast-user-data: write_files[%d].content is required", i)
		}
		encoding, _ := entry["encoding"].(string)
		if _, err := DecodeWriteFileContent(content, encoding); err != nil {
			return fmt.Errorf("cloudblast-user-data: write_files[%d]: %w", i, err)
		}
		if v, ok := entry["permissions"]; ok {
			perm, ok := v.(string)
			if !ok || !permissionsRE.MatchString(perm) {
				return fmt.Errorf("cloudblast-user-data: write_files[%d].permissions must be an octal string", i)
			}
		}
		for _, key := range []string{"append", "defer"} {
			if v, ok := entry[key]; ok {
				if _, isBool := v.(bool); !isBool {
					return fmt.Errorf("cloudblast-user-data: write_files[%d].%s must be a boolean", i, key)
				}
			}
		}
		if v, ok := entry["owner"]; ok {
			if _, isString := v.(string); !isString {
				return fmt.Errorf("cloudblast-user-data: write_files[%d].owner must be a string", i)
			}
		}
	}
	return nil
}

// DecodeWriteFileContent decodes write_files content for the supported encodings.
func DecodeWriteFileContent(content, encoding string) ([]byte, error) {
	switch strings.TrimSpace(encoding) {
	case "", "text":
		return []byte(content), nil
	case "b64":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content))
		if err != nil {
			return nil, fmt.Errorf("invalid b64 content: %w", err)
		}
		return decoded, nil
	case "gzip+b64":
		compressed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content))
		if err != nil {
			return nil, fmt.Errorf("invalid gzip+b64 content: %w", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, fmt.Errorf("invalid gzip stream: %w", err)
		}
		defer zr.Close()
		decoded, err := io.ReadAll(io.LimitReader(zr, 16<<20))
		if err != nil {
			return nil, fmt.Errorf("invalid gzip stream: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported encoding %q", encoding)
	}
}
