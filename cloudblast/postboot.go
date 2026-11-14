package cloudblast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	postBootScriptPath = "/tmp/cloudblast-post-boot.sh"
	bootFinishedPath   = "/var/lib/cloud/instance/boot-finished"
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

// runPostBootScript waits for SSH (and best-effort for the provider
// boot-finished marker) and runs the optional script. Rancher's install.sh is
// not involved here; it runs after Create returns.
func (d *Driver) runPostBootScript(ip string, script []byte) error {
	sshTimeout := d.sshWaitTimeout()
	sshCtx, sshCancel := context.WithTimeout(context.Background(), sshTimeout)
	defer sshCancel()

	cfg := SSHConfig{
		Host:           ip,
		Port:           d.SSHPort,
		User:           d.SSHUser,
		PrivateKeyPath: d.GetSSHKeyPath(),
		Timeout:        sshTimeout,
		RetryInterval:  d.pollEvery(),
	}
	client, err := waitForSSHFunc(sshCtx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	d.waitBootFinishedBestEffort(client)
	return d.executePostBootScript(client, script)
}

func (d *Driver) sshWaitTimeout() time.Duration {
	if timeout := d.readyTimeout(); timeout > sshHandshakeMinTimeout {
		return timeout
	}
	return sshHandshakeMinTimeout
}

// waitBootFinishedBestEffort waits at most 5 minutes for the provider
// boot-finished marker. Timeouts and probe errors are warnings only.
func (d *Driver) waitBootFinishedBestEffort(client *SSHClient) {
	ctx, cancel := context.WithTimeout(context.Background(), bootFinishedWaitTimeout)
	defer cancel()

	start := time.Now()
	for {
		out, err := client.Run(ctx, "test -f "+shellQuote(bootFinishedPath)+" && echo yes || echo no")
		if err == nil && strings.Contains(strings.ToLower(out), "yes") {
			d.debugf("boot-finished marker present after %s", time.Since(start).Round(time.Second))
			return
		}
		if err != nil {
			d.logf("WARNING: boot-finished probe failed (best-effort): %v", err)
			return
		}
		if time.Since(start) >= bootFinishedWaitTimeout {
			break
		}
		if sleepCtx(ctx, d.pollEvery()) != nil {
			break
		}
	}
	d.logf("WARNING: boot-finished marker not seen within %s; continuing", bootFinishedWaitTimeout)
}

func (d *Driver) executePostBootScript(client *SSHClient, script []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), postBootScriptTimeout)
	defer cancel()

	if err := client.WriteFile(ctx, postBootScriptPath, script, 0o600); err != nil {
		return fmt.Errorf("cloudblast: upload post-boot script: %w", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), keyCleanupTimeout)
		defer cleanupCancel()
		if _, err := client.Run(cleanupCtx, "rm -f "+shellQuote(postBootScriptPath)); err != nil {
			d.debugf("remove post-boot script: %v", err)
		}
	}()

	out, err := client.Run(ctx, "sh "+shellQuote(postBootScriptPath))
	d.logf("post-boot script output: %s", truncateOutput(out))
	if err != nil {
		return fmt.Errorf("cloudblast: post-boot script failed: %w", err)
	}
	return nil
}
