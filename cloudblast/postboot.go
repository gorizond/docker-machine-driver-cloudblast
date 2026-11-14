package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	postBootScriptPath = "/tmp/cloudblast-post-boot.sh"
	bootFinishedPath   = "/var/lib/cloud/instance/boot-finished"

	stepBootFinished = "boot-finished"
	stepUpload       = "upload"
	stepRun          = "run"
	stepCleanup      = "cleanup"
)

// waitForSSHFunc is a test seam for post-boot script tests.
var waitForSSHFunc = WaitForSSH

// readPostBootScript reads the flag value: @path, an existing local path, or
// inline script content. Empty content means "no script" (a no-op).
func readPostBootScript(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	if strings.HasPrefix(value, "@") {
		return readPostBootScriptFile(strings.TrimPrefix(value, "@"))
	}
	if !strings.Contains(value, "\n") {
		if info, err := os.Stat(value); err == nil && !info.IsDir() {
			return readPostBootScriptFile(value)
		}
	}
	return []byte(value), nil
}

func readPostBootScriptFile(path string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cloudblast-post-boot-script: read %q: %w", path, err)
	}
	if strings.TrimSpace(string(content)) == "" {
		return nil, nil
	}
	return content, nil
}

// runPostBootScript runs the optional post-boot script over SSH. The whole
// phase (boot-finished probe, upload, run, cleanup) retries on SSH drops until
// max(WaitTimeoutSecs, 10m) expires; Rancher's install.sh runs separately after
// Create returns.
func (d *Driver) runPostBootScript(ctx context.Context, ip string, script []byte) error {
	timeout := d.sshWaitTimeout()
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cfg := SSHConfig{
		Host:           ip,
		Port:           d.SSHPort,
		User:           d.SSHUser,
		PrivateKeyPath: d.GetSSHKeyPath(),
		Timeout:        timeout,
		RetryInterval:  d.pollEvery(),
	}
	client, err := waitForSSHFunc(waitCtx, cfg)
	if err != nil {
		return fmt.Errorf("cloudblast: post-boot SSH connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	probeDeadline := time.Now().Add(bootFinishedWaitTimeout)
	step := stepBootFinished
	drops := 0

	for {
		if waitCtx.Err() != nil {
			return postBootTimeoutError(step, drops, timeout, waitCtx.Err())
		}

		switch step {
		case stepBootFinished:
			done, probeErr := d.probeBootFinished(waitCtx, client)
			if probeErr != nil {
				if isDroppedSession(probeErr) {
					drops++
					if err := d.reconnectPostBoot(waitCtx, cfg, client, step, drops); err != nil {
						return err
					}
					continue
				}
				d.logf("WARNING: boot-finished probe failed (best-effort): %v", probeErr)
				step = stepUpload
				continue
			}
			if done {
				d.debugf("boot-finished marker present; running post-boot script")
				step = stepUpload
				continue
			}
			if time.Now().After(probeDeadline) {
				d.logf("WARNING: boot-finished marker not seen within %s; continuing", bootFinishedWaitTimeout)
				step = stepUpload
				continue
			}
			if sleepCtx(waitCtx, d.pollEvery()) != nil {
				return postBootTimeoutError(step, drops, timeout, waitCtx.Err())
			}

		case stepUpload:
			if err := client.WriteFile(waitCtx, postBootScriptPath, script, 0o600); err != nil {
				if isDroppedSession(err) {
					drops++
					if err := d.reconnectPostBoot(waitCtx, cfg, client, step, drops); err != nil {
						return err
					}
					continue
				}
				return fmt.Errorf("cloudblast: upload post-boot script: %w", err)
			}
			step = stepRun

		case stepRun:
			out, runErr := client.Run(waitCtx, "sh "+shellQuote(postBootScriptPath))
			if out != "" {
				d.logf("post-boot script output: %s", truncateOutput(out))
			}
			if runErr != nil {
				if isDroppedSession(runErr) {
					drops++
					if err := d.reconnectPostBoot(waitCtx, cfg, client, step, drops); err != nil {
						return err
					}
					continue
				}
				return fmt.Errorf("cloudblast: post-boot script failed: %w", runErr)
			}
			step = stepCleanup

		case stepCleanup:
			if _, err := client.Run(waitCtx, "rm -f "+shellQuote(postBootScriptPath)); err != nil {
				if isDroppedSession(err) {
					drops++
					if err := d.reconnectPostBoot(waitCtx, cfg, client, step, drops); err != nil {
						return err
					}
					continue
				}
				d.logf("WARNING: could not remove post-boot script: %v", err)
			}
			return nil
		}
	}
}

func (d *Driver) probeBootFinished(ctx context.Context, client *SSHClient) (bool, error) {
	out, err := client.Run(ctx, "test -f "+shellQuote(bootFinishedPath)+" && echo yes || echo no")
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(out), "yes"), nil
}

func (d *Driver) reconnectPostBoot(ctx context.Context, cfg SSHConfig, client *SSHClient, step string, drops int) error {
	d.logf("SSH session dropped during post-boot %s (attempt %d); reconnecting", step, drops)
	client.drop()

	if err := sleepCtx(ctx, d.pollEvery()); err != nil {
		return postBootTimeoutError(step, drops, d.sshWaitTimeout(), err)
	}
	reconnected, err := waitForSSHFunc(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return postBootTimeoutError(step, drops, d.sshWaitTimeout(), ctx.Err())
		}
		return fmt.Errorf("cloudblast: post-boot reconnect failed at %s (attempt %d): %w", step, drops, err)
	}
	client.client = reconnected.client
	client.runFunc = reconnected.runFunc
	client.writeFunc = reconnected.writeFunc
	return nil
}

func postBootTimeoutError(step string, drops int, timeout time.Duration, cause error) error {
	return fmt.Errorf("cloudblast: post-boot script phase did not finish within %s (step=%s, attempts=%d): %w",
		timeout, step, drops, cause)
}

// isDroppedSession reports whether an SSH command failed because the session
// died (provider cloud-init/reboot), not because the command itself failed.
func isDroppedSession(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var exitMissing *ssh.ExitMissingError
	if errors.As(err, &exitMissing) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"eof",
		"connection reset",
		"unexpected packet",
		"use of closed network connection",
		"broken pipe",
		"client is not connected",
		"client not connected",
		"exited without exit status",
		"session closed",
	} {
		if strings.Contains(msg, fragment) {
			return true
		}
	}
	return false
}

// drop closes and forgets the current connection so the caller can re-dial.
func (c *SSHClient) drop() {
	if c == nil {
		return
	}
	if c.client != nil {
		_ = c.client.Close()
	}
	c.client = nil
	c.runFunc = nil
	c.writeFunc = nil
}

func (d *Driver) sshWaitTimeout() time.Duration {
	if timeout := d.readyTimeout(); timeout > sshHandshakeMinTimeout {
		return timeout
	}
	return sshHandshakeMinTimeout
}
