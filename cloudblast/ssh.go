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
// the timeout expires. Authentication failures are returned immediately.
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
	for {
		client, dialErr := dialSSH(waitCtx, address, config)
		if dialErr == nil {
			log.Debugf("cloudblast ssh: connected to %s@%s", cfg.User, address)
			return &SSHClient{client: client}, nil
		}
		lastErr = dialErr
		if isAuthFailure(dialErr) {
			return nil, fmt.Errorf("cloudblast ssh: authentication to %s failed: %w", address, dialErr)
		}
		log.Debugf("cloudblast ssh: waiting for %s: %v", address, dialErr)

		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("cloudblast ssh: handshake with %s timed out after %s: %w", address, cfg.Timeout, lastErr)
		case <-time.After(cfg.RetryInterval):
		}
	}
}

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

// Run executes a command and returns combined stdout/stderr. Output is masked.
func (c *SSHClient) Run(ctx context.Context, cmd string) (string, error) {
	return c.run(ctx, cmd, nil)
}

// WriteFile writes content to path with the given mode using stdin, so the
// content is never embedded into a shell command.
func (c *SSHClient) WriteFile(ctx context.Context, path string, content []byte, perm os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("cloudblast ssh: path is required")
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

// RunWithProgress runs a command and calls progress every interval while it is
// executing. Used to log long cloud-init waits without leaking command output.
func (c *SSHClient) RunWithProgress(ctx context.Context, cmd string, interval time.Duration, progress func(elapsed time.Duration)) (string, error) {
	if progress == nil || interval <= 0 {
		return c.Run(ctx, cmd)
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				progress(time.Since(start))
			}
		}
	}()
	out, err := c.Run(ctx, cmd)
	close(done)
	return out, err
}

// WaitCloudInit waits for the provider cloud-init to finish, so package
// installation does not race with dpkg locks. If the boot-finished marker
// already exists, cloud-init is considered complete. It never runs
// "cloud-init clean" or "cloud-init init".
func (c *SSHClient) WaitCloudInit(ctx context.Context, timeout time.Duration, progress func(elapsed time.Duration)) error {
	if timeout <= 0 {
		timeout = cloudInitMinTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	marker, err := c.Run(waitCtx, "test -f /var/lib/cloud/instance/boot-finished && echo yes || echo no")
	if err != nil {
		return fmt.Errorf("cloudblast: check cloud-init boot-finished: %w", err)
	}
	if strings.Contains(marker, "yes") {
		log.Debugf("cloudblast ssh: boot-finished marker present, cloud-init already done")
		return nil
	}

	out, err := c.RunWithProgress(waitCtx, "cloud-init status --wait", cloudInitProgressInterval, progress)
	if err != nil {
		return fmt.Errorf("cloudblast: cloud-init did not finish: %w", err)
	}
	if strings.Contains(out, "status: error") || strings.Contains(out, "status: degraded") {
		return fmt.Errorf("cloudblast: cloud-init finished with an error: %s", strings.TrimSpace(out))
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
