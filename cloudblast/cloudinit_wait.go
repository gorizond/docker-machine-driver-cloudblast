package cloudblast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/log"
	"golang.org/x/crypto/ssh"
)

// waitForSSHFunc is a test seam for cloud-init reconnect tests.
var waitForSSHFunc = WaitForSSH

// cloudInitPollInterval is the pause between short cloud-init status polls.
var cloudInitPollInterval = 5 * time.Second

const (
	cloudInitBootFinishedCmd = "test -f /var/lib/cloud/instance/boot-finished && echo yes || echo no"
	cloudInitStatusCmd       = "cloud-init status --format=json"
)

// WaitCloudInit waits for provider cloud-init to finish by polling short
// commands. The long-lived "cloud-init status --wait" session is not used:
// CloudBlast's cloud-init restarts sshd/network and kills it. Dropped sessions
// are closed and re-dialled with the same SSHConfig; the boot-finished marker
// short-circuits the wait. It never runs "cloud-init clean" or "cloud-init init".
func (c *SSHClient) WaitCloudInit(ctx context.Context, cfg SSHConfig, timeout time.Duration, progress func(elapsed time.Duration, attempt int, status string)) error {
	if timeout <= 0 {
		timeout = cloudInitMinTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	attempt := 0
	lastStatus := "unknown"
	lastProgress := time.Now()
	var lastErr error

	report := func(status string) {
		if progress == nil || time.Since(lastProgress) < cloudInitProgressInterval {
			return
		}
		progress(time.Since(start).Round(time.Second), attempt, status)
		lastProgress = time.Now()
	}
	timeoutErr := func() error {
		detail := ""
		if lastErr != nil {
			detail = fmt.Sprintf(", last_error=%v", lastErr)
		}
		return fmt.Errorf("cloudblast: cloud-init did not finish within %s (elapsed=%s, attempts=%d, last_status=%q%s)",
			timeout, time.Since(start).Round(time.Second), attempt, lastStatus, detail)
	}
	pollAgain := func() bool {
		return sleepCtx(waitCtx, cloudInitPollInterval) == nil
	}

	for {
		attempt++
		if c == nil {
			return errors.New("cloudblast ssh: client is required")
		}
		if c.client == nil && c.runFunc == nil {
			reconnected, reconnectErr := waitForSSHFunc(waitCtx, cfg)
			if reconnectErr != nil {
				lastErr = reconnectErr
				report("reconnecting")
				if !pollAgain() {
					return timeoutErr()
				}
				continue
			}
			c.client = reconnected.client
			c.runFunc = reconnected.runFunc
			log.Debugf("cloudblast ssh: reconnected for cloud-init poll (attempt %d)", attempt)
		}

		marker, markerErr := c.Run(waitCtx, cloudInitBootFinishedCmd)
		if markerErr == nil && strings.Contains(strings.ToLower(marker), "yes") {
			log.Debugf("cloudblast ssh: boot-finished marker present (attempt %d)", attempt)
			return nil
		}
		if markerErr != nil {
			if isDroppedSession(markerErr) {
				lastErr = markerErr
				log.Debugf("cloudblast ssh: session dropped during boot-finished check (attempt %d): %s", attempt, sshFailureReason(markerErr))
				c.drop()
				report("reconnecting")
				if !pollAgain() {
					return timeoutErr()
				}
				continue
			}
			lastErr = markerErr
			log.Debugf("cloudblast ssh: boot-finished check failed (attempt %d): %s", attempt, sshFailureReason(markerErr))
			report(lastStatus)
			if !pollAgain() {
				return timeoutErr()
			}
			continue
		}

		out, statusErr := c.Run(waitCtx, cloudInitStatusCmd)
		if statusErr != nil && isDroppedSession(statusErr) {
			lastErr = statusErr
			log.Debugf("cloudblast ssh: session dropped during cloud-init status (attempt %d): %s", attempt, sshFailureReason(statusErr))
			c.drop()
			report("reconnecting")
			if !pollAgain() {
				return timeoutErr()
			}
			continue
		}

		status, detail, parseErr := parseCloudInitStatus(out)
		if parseErr != nil {
			lastErr = statusErr
			if lastErr == nil {
				lastErr = parseErr
			}
			log.Debugf("cloudblast ssh: cloud-init status poll failed (attempt %d): %v", attempt, lastErr)
			report(lastStatus)
			if !pollAgain() {
				return timeoutErr()
			}
			continue
		}

		lastStatus = status
		switch status {
		case "done", "disabled":
			log.Debugf("cloudblast ssh: cloud-init status=%s (attempt %d, elapsed=%s)", status, attempt, time.Since(start).Round(time.Second))
			return nil
		case "error":
			if detail != "" {
				return fmt.Errorf("cloudblast: cloud-init finished with error: %s", detail)
			}
			return errors.New("cloudblast: cloud-init finished with error")
		}

		if statusErr != nil {
			lastErr = statusErr
		} else {
			lastErr = nil
		}
		report(status)
		if !pollAgain() {
			return timeoutErr()
		}
	}
}

// isDroppedSession reports whether a command failed because the SSH session
// died (sshd/network restart), not because the command itself failed.
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
		"exited without exit status",
		"connection reset",
		"broken pipe",
		"use of closed network connection",
		"client is not connected",
		"session closed",
	} {
		if strings.Contains(msg, fragment) {
			return true
		}
	}
	return false
}

// drop closes and forgets the current connection so the poll loop re-dials.
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

// Reconnect closes the current connection and dials again with the same config.
func (c *SSHClient) Reconnect(ctx context.Context, cfg SSHConfig) error {
	c.drop()
	reconnected, err := waitForSSHFunc(ctx, cfg)
	if err != nil {
		return err
	}
	c.client = reconnected.client
	c.runFunc = reconnected.runFunc
	c.writeFunc = reconnected.writeFunc
	return nil
}

type cloudInitStatusPayload struct {
	Status            string   `json:"status"`
	Errors            []string `json:"errors"`
	RecoverableErrors []string `json:"recoverable_errors"`
}

func parseCloudInitStatus(out string) (status, detail string, err error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return "", "", errors.New("empty cloud-init status output")
	}
	var payload cloudInitStatusPayload
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return "", "", fmt.Errorf("parse cloud-init status JSON: %w", err)
	}
	status = strings.ToLower(strings.TrimSpace(payload.Status))
	if status == "" {
		return "", "", errors.New("cloud-init status is empty")
	}
	details := append([]string{}, payload.Errors...)
	details = append(details, payload.RecoverableErrors...)
	return status, strings.Join(details, "; "), nil
}
