package cloudblast

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/log"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHWaitTimeout   = 5 * time.Minute
	defaultSSHRetryInterval = 5 * time.Second
	sshHandshakeTimeout     = 20 * time.Second
)

// SSHConfig describes how to reach a fresh CloudBlast node.
type SSHConfig struct {
	Host           string
	Port           int
	User           string
	PrivateKeyPath string
	// Timeout bounds the whole wait-for-handshake phase.
	Timeout time.Duration
	// RetryInterval is the pause between handshake attempts.
	RetryInterval time.Duration
}

// SSHClient is a small command runner over one SSH connection.
type SSHClient struct {
	client *ssh.Client
	// runFunc and writeFunc are test seams; production code uses client.
	runFunc   func(context.Context, string) (string, error)
	writeFunc func(context.Context, string, []byte, os.FileMode) error
}

// LoadPrivateKey reads an unencrypted OpenSSH/PEM private key.
func LoadPrivateKey(path string) (ssh.Signer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cloudblast ssh: read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		if strings.Contains(err.Error(), "encrypted") {
			return nil, errors.New("cloudblast ssh: encrypted private keys are not supported")
		}
		return nil, fmt.Errorf("cloudblast ssh: parse private key: %w", err)
	}
	return signer, nil
}

// WaitForSSH retries the TCP+SSH handshake until the node accepts the key or
// the timeout expires. Authentication failures are retried too: CloudBlast
// injects the registered key via its own cloud-init after boot, so publickey
// auth can transiently fail on the first attempts. Key-file and configuration
// errors are fatal and abort immediately.
func WaitForSSH(ctx context.Context, cfg SSHConfig) (*SSHClient, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("cloudblast ssh: host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = defaultSSHPort
	}
	if cfg.User == "" {
		cfg.User = defaultSSHUser
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSSHWaitTimeout
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = defaultSSHRetryInterval
	}

	signer, err := LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	waitCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	address := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	config := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // brand-new VM, host key is not known yet
	}

	var lastErr error
	attempt := 0
	for {
		attempt++
		client, dialErr := dialSSHFunc(waitCtx, address, config)
		if dialErr == nil {
			log.Debugf("cloudblast ssh: connected to %s@%s after %d attempt(s)", cfg.User, address, attempt)
			return &SSHClient{client: client}, nil
		}
		lastErr = dialErr
		log.Debugf("cloudblast ssh: attempt %d for %s failed: %s", attempt, address, sshFailureReason(dialErr))

		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("cloudblast ssh: handshake with %s timed out after %s (%d attempts): %w",
				address, cfg.Timeout, attempt, lastErr)
		case <-time.After(cfg.RetryInterval):
		}
	}
}

// dialSSHFunc is a test seam; production code uses dialSSH.
var dialSSHFunc = dialSSH

func dialSSH(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := &net.Dialer{Timeout: sshHandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sshHandshakeTimeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "no supported methods remain")
}

// sshFailureReason classifies an attempt error for debug logging. It never
// contains key material: handshake errors only carry method names.
func sshFailureReason(err error) string {
	if isAuthFailure(err) {
		return "authentication not ready yet (key may not be injected)"
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}

// Run executes a command and returns combined stdout/stderr. Output is masked.
func (c *SSHClient) Run(ctx context.Context, cmd string) (string, error) {
	if c != nil && c.runFunc != nil {
		return c.runFunc(ctx, cmd)
	}
	return c.run(ctx, cmd, nil)
}

// WriteFile writes content to path with the given mode using stdin, so the
// content is never embedded into a shell command.
func (c *SSHClient) WriteFile(ctx context.Context, path string, content []byte, perm os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("cloudblast ssh: path is required")
	}
	if c != nil && c.writeFunc != nil {
		return c.writeFunc(ctx, path, content, perm)
	}
	dir := path[:strings.LastIndex(path, "/")+1]
	if dir == "" {
		dir = "/"
	}
	mode := fmt.Sprintf("%04o", perm.Perm())
	cmd := "mkdir -p " + shellQuote(dir) + " && cat > " + shellQuote(path) + " && chmod " + mode + " " + shellQuote(path)
	if _, err := c.run(ctx, cmd, bytes.NewReader(content)); err != nil {
		return fmt.Errorf("cloudblast ssh: write %s: %w", path, err)
	}
	return nil
}

// Close closes the SSH connection. Safe on nil.
func (c *SSHClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

func (c *SSHClient) run(ctx context.Context, cmd string, stdin io.Reader) (string, error) {
	if c == nil || c.client == nil {
		return "", errors.New("cloudblast ssh: client is not connected")
	}
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("cloudblast ssh: open session: %w", err)
	}
	defer session.Close()
	if stdin != nil {
		session.Stdin = stdin
	}

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return maskSecrets(out.String()), fmt.Errorf("cloudblast ssh: command timed out: %w", ctx.Err())
	case runErr := <-done:
		masked := maskSecrets(out.String())
		if runErr != nil {
			return masked, fmt.Errorf("%w: %s", runErr, truncateOutput(masked))
		}
		return masked, nil
	}
}

func truncateOutput(s string) string {
	const limit = 4096
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
