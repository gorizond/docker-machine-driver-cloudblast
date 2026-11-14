package cloudblast

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	preserveHostnamePath   = "/etc/cloud/cloud.cfg.d/99-cloudblast-preserve-hostname.cfg"
	preserveHostnameConfig = "preserve_hostname: true\n"
	etcHostnamePath        = "/etc/hostname"
)

// hostnames are limited to 64 chars by the kernel (HOST_NAME_MAX) and must not
// contain whitespace/newlines that could corrupt /etc/hostname.
var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$`)

// desiredHostname picks the hostname to persist after cloud-config apply:
// user-data hostname first, then the docker-machine name, then the CloudBlast
// server hostname.
func (d *Driver) desiredHostname(ud *UserData, serverHostname string) string {
	if hostname := ud.Hostname(); hostname != "" {
		return hostname
	}
	if machineName := strings.TrimSpace(d.MachineName); machineName != "" {
		return machineName
	}
	return strings.TrimSpace(serverHostname)
}

// persistHostname makes the hostname survive provider cloud-init/reboot:
// preserve_hostname is pinned in cloud.cfg.d, /etc/hostname is written and the
// live hostname is set. It is idempotent and skips empty names with a warning.
func (d *Driver) persistHostname(ctx context.Context, client *SSHClient, cfg SSHConfig, desired string) error {
	desired = strings.TrimSpace(desired)
	if desired == "" {
		d.logf("WARNING: no desired hostname found; keeping provider hostname")
		return nil
	}
	if !hostnameRE.MatchString(desired) {
		return fmt.Errorf("cloudblast: desired hostname %q is not a valid hostname", desired)
	}

	err := d.applyHostname(ctx, client, desired)
	if err != nil && isDroppedSession(err) {
		d.logf("SSH session dropped while setting hostname; reconnecting")
		if reconnectErr := client.Reconnect(ctx, cfg); reconnectErr != nil {
			return fmt.Errorf("cloudblast: set hostname %q: reconnect failed: %w", desired, reconnectErr)
		}
		err = d.applyHostname(ctx, client, desired)
	}
	if err != nil {
		return fmt.Errorf("cloudblast: persist hostname %q: %w", desired, err)
	}

	d.verifyHostname(ctx, client, desired)
	return nil
}

func (d *Driver) applyHostname(ctx context.Context, client *SSHClient, hostname string) error {
	if err := client.WriteFile(ctx, preserveHostnamePath, []byte(preserveHostnameConfig), 0o644); err != nil {
		return err
	}
	if err := client.WriteFile(ctx, etcHostnamePath, []byte(hostname+"\n"), 0o644); err != nil {
		return err
	}
	if _, err := client.Run(ctx, "hostnamectl set-hostname "+shellQuote(hostname)); err != nil {
		if isDroppedSession(err) {
			return err
		}
		d.debugf("hostnamectl set-hostname failed (%v); falling back to hostname", err)
		if _, fallbackErr := client.Run(ctx, "hostname "+shellQuote(hostname)); fallbackErr != nil {
			return fallbackErr
		}
	}
	return nil
}

// verifyHostname is best-effort: a transient read failure must not fail Create.
func (d *Driver) verifyHostname(ctx context.Context, client *SSHClient, want string) {
	runtimeName, runtimeErr := client.Run(ctx, "hostname")
	staticName, staticErr := client.Run(ctx, "hostnamectl --static")

	runtimeValue := strings.TrimSpace(runtimeName)
	staticValue := strings.TrimSpace(staticName)
	d.logf("hostname verification: runtime=%q static=%q desired=%q", runtimeValue, staticValue, want)

	if runtimeErr != nil {
		d.logf("WARNING: hostname verification failed (best-effort): %v", runtimeErr)
	} else if runtimeValue != want {
		d.logf("WARNING: runtime hostname %q differs from desired %q", runtimeValue, want)
	}
	if staticErr != nil {
		d.debugf("hostnamectl --static unavailable: %v", staticErr)
	} else if staticValue != want {
		d.logf("WARNING: persistent hostname %q differs from desired %q", staticValue, want)
	}
}
