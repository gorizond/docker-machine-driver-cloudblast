package cloudblast

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Hostname returns the deterministic CloudBlast hostname for this machine.
// Long names are truncated to 191 characters with a short hash suffix so the
// result stays unique and stable across retries.
func (d *Driver) Hostname() string {
	name := d.HostnamePrefix + d.MachineName
	if strings.TrimSpace(name) == "" {
		name = "cloudblast"
	}
	return truncateWithHash(name, maxHostnameLen)
}

// sshKeyName builds the registered key name (the API limit is 40 characters).
func sshKeyName(machineName string) string {
	name := "cloudblast-" + machineName
	if strings.TrimSpace(machineName) == "" {
		name = "cloudblast"
	}
	return truncateWithHash(name, maxSSHKeyNameLen)
}

// truncateWithHash shortens value to max characters and, when truncation is
// needed, replaces the tail with "-" plus 6 hex chars of the full-value hash.
func truncateWithHash(value string, max int) string {
	if len(value) <= max {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	suffix := "-" + hex.EncodeToString(sum[:3])
	keep := max - len(suffix)
	if keep < 0 {
		keep = 0
	}
	return value[:keep] + suffix
}
