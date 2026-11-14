package cloudblast

import (
	"context"
	"fmt"
	"time"
)

// provisionNode waits for SSH, waits for the provider cloud-init to finish and
// applies the merged cloud-config before Create returns. SSH, cloud-init and
// the apply step each get their own timeout so a 600 s readiness budget cannot
// cut a long cloud-init run short.
func (d *Driver) provisionNode(ip string, ud *UserData, desiredHostname string) error {
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
	client, err := WaitForSSH(sshCtx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	cloudInitTimeout := d.cloudInitTimeout()
	d.logf("waiting for cloud-init (timeout=%s)", cloudInitTimeout)
	progress := func(elapsed time.Duration, attempt int, status string) {
		d.logf("waiting for cloud-init, elapsed=%s attempt=%d status=%s", elapsed.Round(time.Second), attempt, status)
	}
	if err := client.WaitCloudInit(context.Background(), cfg, cloudInitTimeout, progress); err != nil {
		return err
	}

	applyCtx, applyCancel := context.WithTimeout(context.Background(), cloudConfigApplyTimeout)
	defer applyCancel()
	applied, err := ApplyCloudConfig(applyCtx, client, ud.TmpPath, CloudInitModules(ud))
	d.AppliedModules = applied
	if err != nil {
		return fmt.Errorf("cloudblast: provisioning failed after modules %v: %w", applied, err)
	}

	hostnameCtx, hostnameCancel := context.WithTimeout(context.Background(), hostnameApplyTimeout)
	defer hostnameCancel()
	if err := d.persistHostname(hostnameCtx, client, cfg, desiredHostname); err != nil {
		return err
	}
	return nil
}

func (d *Driver) sshWaitTimeout() time.Duration {
	if timeout := d.readyTimeout(); timeout > sshHandshakeMinTimeout {
		return timeout
	}
	return sshHandshakeMinTimeout
}

// cloudInitTimeout is max(WaitTimeoutSecs, 15 min): Ubuntu images can spend
// well over 600 s in apt/unattended-upgrades during provider cloud-init.
func (d *Driver) cloudInitTimeout() time.Duration {
	if timeout := d.readyTimeout(); timeout > cloudInitMinTimeout {
		return timeout
	}
	return cloudInitMinTimeout
}
