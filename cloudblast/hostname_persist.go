package cloudblast

import (
	"context"
	"fmt"
	"strings"
)

const (
	preserveHostnamePath   = "/etc/cloud/cloud.cfg.d/99-cloudblast-preserve-hostname.cfg"
	preserveHostnameConfig = "preserve_hostname: true\n"
	etcHostnamePath        = "/etc/hostname"
	hostnameUnitPath       = "/etc/systemd/system/cloudblast-hostname.service"
	hostnameUnitEnableCmd  = "systemctl daemon-reload && systemctl enable cloudblast-hostname.service && systemctl start cloudblast-hostname.service"
)

// hostnameUnitTemplate re-asserts the hostname on every boot, after cloud-init
// had a chance to overwrite it. The name is RFC1123-validated before use, so it
// cannot inject shell metacharacters into the single-quoted sh -c command.
const hostnameUnitTemplate = `[Unit]
Description=CloudBlast persistent hostname
After=cloud-init.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'hostnamectl set-hostname %[1]s 2>/dev/null || hostname %[1]s; printf "%%s\n" %[1]s > /etc/hostname'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

func hostnameUnitContent(hostname string) string {
	return fmt.Sprintf(hostnameUnitTemplate, hostname)
}

// isValidHostname enforces RFC1123 labels, HOST_NAME_MAX (64) and rejects
// whitespace/newlines that could corrupt /etc/hostname or the systemd unit.
func isValidHostname(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

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
	if !isValidHostname(desired) {
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
	return d.installHostnameUnit(ctx, client, hostname)
}

// installHostnameUnit installs a systemd oneshot that re-applies the hostname
// after cloud-init on every boot. Without systemd it logs a warning and leaves
// the preserve_hostname/hostnamectl path in place; Create is not failed.
func (d *Driver) installHostnameUnit(ctx context.Context, client *SSHClient, hostname string) error {
	content := hostnameUnitContent(hostname)
	if err := client.WriteFile(ctx, hostnameUnitPath, []byte(content), 0o644); err != nil {
		if isDroppedSession(err) {
			return err
		}
		d.logf("WARNING: cannot install cloudblast-hostname.service (%v); relying on preserve_hostname", err)
		return nil
	}

	if _, err := client.Run(ctx, hostnameUnitEnableCmd); err != nil {
		if isDroppedSession(err) {
			return err
		}
		d.logf("WARNING: systemd is unavailable (%v); relying on preserve_hostname", err)
		return nil
	}
	d.logf("cloudblast-hostname.service installed, enabled and started")
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
