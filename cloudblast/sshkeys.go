package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxSSHKeyNameLen = 40

// SSHKey is a stored CloudBlast SSH key.
type SSHKey struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
}

// FingerprintPublicKey returns the SHA256 fingerprint of an authorized_keys line.
func FingerprintPublicKey(publicKey string) (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return "", fmt.Errorf("cloudblast: parse SSH public key: %w", err)
	}
	return ssh.FingerprintSHA256(pk), nil
}

// CreateSSHKey registers a key. Names are limited to 40 characters by the API.
func (c *Client) CreateSSHKey(ctx context.Context, name, publicKey string) (*SSHKey, error) {
	name = strings.TrimSpace(name)
	publicKey = strings.TrimSpace(publicKey)
	if name == "" {
		return nil, errors.New("cloudblast: SSH key name is required")
	}
	if len(name) > maxSSHKeyNameLen {
		return nil, fmt.Errorf("cloudblast: SSH key name must be at most %d characters", maxSSHKeyNameLen)
	}
	if publicKey == "" {
		return nil, errors.New("cloudblast: SSH public key is required")
	}
	body := map[string]string{"name": name, "public_key": publicKey}
	raw, _, err := c.do(ctx, http.MethodPost, "/ssh-keys", nil, body)
	if err != nil {
		return nil, err
	}
	return decodeOne[SSHKey](raw)
}

// ListSSHKeys returns all SSH keys in the account.
func (c *Client) ListSSHKeys(ctx context.Context) ([]SSHKey, error) {
	raw, _, err := c.do(ctx, http.MethodGet, "/ssh-keys", nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeMany[SSHKey](raw)
}

// DeleteSSHKey removes a key. A missing key is treated as success.
func (c *Client) DeleteSSHKey(ctx context.Context, id int) error {
	if id <= 0 {
		return errors.New("cloudblast: SSH key id must be > 0")
	}
	_, _, err := c.do(ctx, http.MethodDelete, "/ssh-keys/"+url.PathEscape(strconv.Itoa(id)), nil, nil)
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

// FindSSHKeyByFingerprint returns an existing key with the same fingerprint, or
// nil when none exists. Used to make key registration idempotent.
func (c *Client) FindSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*SSHKey, error) {
	want := normalizeFingerprint(fingerprint)
	if want == "" {
		return nil, errors.New("cloudblast: SSH key fingerprint is required")
	}
	keys, err := c.ListSSHKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if normalizeFingerprint(keys[i].Fingerprint) == want {
			return &keys[i], nil
		}
	}
	return nil, nil
}
