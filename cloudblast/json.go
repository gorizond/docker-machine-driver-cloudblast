package cloudblast

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func decodeOne[T any](raw json.RawMessage) (*T, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("cloudblast: empty response body")
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("cloudblast: decode response: %w", err)
	}
	return &v, nil
}

func decodeMany[T any](raw json.RawMessage) ([]T, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var v []T
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("cloudblast: decode response list: %w", err)
	}
	return v, nil
}

// normalizeFingerprint makes SHA256 fingerprints comparable regardless of the
// "SHA256:" prefix, padding and letter case.
func normalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	fp = strings.TrimPrefix(fp, "SHA256:")
	fp = strings.TrimRight(fp, "=")
	return strings.ToLower(fp)
}
