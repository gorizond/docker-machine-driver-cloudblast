package cloudblast

import (
	"context"
	"strings"
	"time"
)

// waitForBootFinished delays Create until the provider cloud-init writes the
// boot-finished marker (CloudBlast package_upgrade reboots around 10 minutes).
// Drops reconnect and retry; a timeout is a warning, never a Create failure.
func (d *Driver) waitForBootFinished(ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := SSHConfig{
		Host:           ip,
		Port:           d.SSHPort,
		User:           d.SSHUser,
		PrivateKeyPath: d.GetSSHKeyPath(),
		Timeout:        timeout,
		RetryInterval:  d.pollEvery(),
	}
	client, err := waitForSSHFunc(ctx, cfg)
	if err != nil {
		d.logf("WARNING: cannot wait for provider boot-finished: %v; continuing", err)
		return false
	}
	defer func() { _ = client.Close() }()

	start := time.Now()
	lastProgress := start
	for {
		out, runErr := client.Run(ctx, "test -f "+shellQuote(bootFinishedPath)+" && echo yes || echo no")
		if runErr == nil && strings.Contains(strings.ToLower(out), "yes") {
			d.logf("provider boot-finished after %s", time.Since(start).Round(time.Second))
			return true
		}
		if runErr != nil {
			if isDroppedSession(runErr) {
				d.logf("SSH session dropped while waiting for provider boot-finished; reconnecting")
				client.drop()
				if sleepCtx(ctx, d.pollEvery()) != nil {
					break
				}
				reconnected, reconnectErr := waitForSSHFunc(ctx, cfg)
				if reconnectErr != nil {
					d.logf("WARNING: boot-finished reconnect failed: %v; continuing", reconnectErr)
					break
				}
				adoptSSHClient(client, reconnected)
				continue
			}
			d.debugf("boot-finished probe failed (best-effort): %v", runErr)
		}
		if time.Since(lastProgress) >= bootFinishedProgressInterval {
			d.logf("waiting for provider boot-finished, elapsed=%s", time.Since(start).Round(time.Second))
			lastProgress = time.Now()
		}
		if sleepCtx(ctx, d.pollEvery()) != nil {
			break
		}
	}
	d.logf("WARNING: provider boot-finished not seen within %s; continuing; Rancher will attempt install.sh", timeout)
	return false
}

func adoptSSHClient(dst, src *SSHClient) {
	dst.client = src.client
	dst.runFunc = src.runFunc
	dst.writeFunc = src.writeFunc
}

func (d *Driver) bootFinishedTimeout() time.Duration {
	seconds := d.BootFinishedTimeoutSecs
	if seconds <= 0 {
		seconds = defaultBootFinishedTimeoutSecs
	}
	return time.Duration(seconds) * time.Second
}
