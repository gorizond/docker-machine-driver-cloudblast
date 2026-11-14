package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	machinessh "github.com/docker/machine/libmachine/ssh"
)

// Create provisions a CloudBlast server and applies the merged cloud-config.
// Any failure after the server exists triggers a compensating delete.
func (d *Driver) Create() (err error) {
	if err := d.PreCreateCheck(); err != nil {
		return err
	}

	keyPath := d.GetSSHKeyPath()
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("cloudblast: create SSH key directory: %w", err)
	}
	if err := machinessh.GenerateSSHKey(keyPath); err != nil {
		return fmt.Errorf("cloudblast: generate SSH key: %w", err)
	}
	pubKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return fmt.Errorf("cloudblast: read SSH public key: %w", err)
	}

	ud, err := LoadUserData(d.UserDataFlag)
	if err != nil {
		return err
	}
	defer func() { _ = ud.Cleanup() }()
	d.UserDataSHA256 = ud.SHA256
	d.UserDataTmpPath = ud.TmpPath
	d.logUserDataSummary(ud)

	ctx, cancel := context.WithTimeout(context.Background(), d.readyTimeout())
	defer cancel()

	api := d.newClient()
	_, keyCreated, err := d.ensureSSHKey(ctx, api, strings.TrimSpace(string(pubKey)))
	if err != nil {
		return err
	}

	hostname := d.Hostname()
	if strings.TrimSpace(hostname) == "" {
		return errors.New("cloudblast: cannot build hostname: machine name is empty")
	}
	request := CreateServerRequest{
		PlanID:       d.PlanID,
		LocationID:   d.LocationID,
		TemplateSlug: d.TemplateSlug,
		Hostname:     hostname,
		SSHKeyIDs:    []int{d.SSHKeyID},
	}

	server, err := d.createOrAdopt(ctx, api, request, hostname)
	if err != nil {
		if keyCreated {
			d.cleanupOrphanKey(api)
		}
		return err
	}
	d.VMUUID = server.UUID
	d.logf("server ready to provision uuid=%s hostname=%s", server.UUID, hostname)

	defer func() {
		if err == nil {
			return
		}
		if compErr := d.compensateCreate(api, server.UUID, keyCreated); compErr != nil {
			err = fmt.Errorf("%w; %v", err, compErr)
		}
	}()

	creds, err := d.waitServerReady(ctx, api, server.UUID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(creds.IPv4) == "" {
		return fmt.Errorf("cloudblast: server %s has no IPv4 address: IPv6-only is not supported", server.UUID)
	}
	d.BaseDriver.IPAddress = creds.IPv4

	if err := d.provisionNode(creds.IPv4, ud); err != nil {
		return err
	}
	d.logf("server %s provisioned with modules %v", server.UUID, d.AppliedModules)
	return nil
}

// createOrAdopt posts the create request once. If the request fails in a way
// that may have reached CloudBlast (timeout/5xx/429/409), it reconciles by
// hostname: exactly one match is adopted, zero allows one POST retry after the
// reconcile, more than one is an error and nothing is deleted.
func (d *Driver) createOrAdopt(ctx context.Context, api *Client, request CreateServerRequest, hostname string) (*Server, error) {
	server, err := api.CreateServer(ctx, request)
	if err == nil {
		return server, nil
	}
	if !shouldReconcileCreateError(err) {
		return nil, err
	}
	d.logf("create failed (%v); reconciling hostname %q", err, hostname)

	servers, listErr := api.ListServers(ctx)
	if listErr != nil {
		return nil, fmt.Errorf("%w; reconcile failed: %v", err, listErr)
	}
	existing, create, selectErr := SelectServerByHostname(servers, hostname)
	if selectErr != nil {
		return nil, selectErr
	}
	if !create && existing != nil {
		d.logf("adopting existing server uuid=%s hostname=%s", existing.UUID, hostname)
		return existing, nil
	}
	// Reconciled: the failed POST did not create a server, so one safe retry
	// is allowed (never retried without this reconcile).
	d.logf("reconcile found no server for hostname %q; retrying create", hostname)
	return api.CreateServer(ctx, request)
}

func shouldReconcileCreateError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 409 || apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
	}
	return true // network error or timeout: the POST may have been accepted
}

func (d *Driver) ensureSSHKey(ctx context.Context, api *Client, publicKey string) (*SSHKey, bool, error) {
	fingerprint, err := FingerprintPublicKey(publicKey)
	if err != nil {
		return nil, false, err
	}
	d.SSHKeyFingerprint = fingerprint

	existing, err := api.FindSSHKeyByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		d.SSHKeyID = existing.ID
		d.debugf("reusing SSH key id=%d fingerprint=%s", existing.ID, fingerprint)
		return existing, false, nil
	}

	key, err := api.CreateSSHKey(ctx, sshKeyName(d.MachineName), publicKey)
	if err != nil {
		return nil, false, err
	}
	d.SSHKeyID = key.ID
	d.logf("registered SSH key id=%d fingerprint=%s", key.ID, fingerprint)
	return key, true, nil
}

// waitServerReady polls until state=running, server_status is empty and
// password_status=ready. Install/deletion failures abort immediately.
func (d *Driver) waitServerReady(ctx context.Context, api *Client, uuid string) (*Credentials, error) {
	deadline := time.Now().Add(d.readyTimeout())
	var lastState, lastStatus, lastPassword string

	for {
		st, err := api.GetServerStatus(ctx, uuid)
		if err != nil {
			return nil, err
		}
		lastState = st.State
		lastStatus = ""
		if st.ServerStatus != nil {
			lastStatus = *st.ServerStatus
			if lastStatus == "install_failed" || lastStatus == "deletion_failed" {
				return nil, fmt.Errorf("cloudblast: server %s failed with status %q", uuid, lastStatus)
			}
		}
		if st.State == "running" && strings.TrimSpace(lastStatus) == "" {
			creds, err := api.GetServerCredentials(ctx, uuid)
			if err != nil {
				return nil, err
			}
			lastPassword = creds.PasswordStatus
			if creds.PasswordStatus == "ready" {
				return creds, nil
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("cloudblast: server %s did not become ready within %s (state=%q server_status=%q password_status=%q)",
				uuid, d.readyTimeout(), lastState, lastStatus, lastPassword)
		}
		if err := sleepCtx(ctx, d.pollEvery()); err != nil {
			return nil, fmt.Errorf("cloudblast: waiting for server %s readiness: %w", uuid, err)
		}
	}
}

// provisionNode waits for SSH, waits for the provider cloud-init to finish and
// applies the merged cloud-config before Create returns. SSH, cloud-init and
// the apply step each get their own timeout so a 600 s readiness budget cannot
// cut a long cloud-init run short.
func (d *Driver) provisionNode(ip string, ud *UserData) error {
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
	progress := func(elapsed time.Duration) {
		d.logf("waiting for cloud-init, elapsed=%s", elapsed.Round(time.Second))
	}
	if err := client.WaitCloudInit(context.Background(), cloudInitTimeout, progress); err != nil {
		return err
	}

	applyCtx, applyCancel := context.WithTimeout(context.Background(), cloudConfigApplyTimeout)
	defer applyCancel()
	applied, err := ApplyCloudConfig(applyCtx, client, ud.TmpPath, CloudInitModules(ud))
	d.AppliedModules = applied
	if err != nil {
		return fmt.Errorf("cloudblast: provisioning failed after modules %v: %w", applied, err)
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

// compensateCreate removes a half-created server and its unused key. The
// returned error is appended to the original one by Create.
func (d *Driver) compensateCreate(api *Client, uuid string, cleanupKey bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), compensationTimeout)
	defer cancel()

	if err := api.DeleteServer(ctx, uuid, d.KeepIPs); err != nil {
		return fmt.Errorf("CloudBlast server %s was not deleted and may still be billed; delete it manually: %w", uuid, err)
	}
	if cleanupKey {
		d.cleanupSSHKey(ctx, api)
	}
	d.VMUUID = ""
	d.BaseDriver.IPAddress = ""
	return nil
}

func (d *Driver) cleanupOrphanKey(api *Client) {
	ctx, cancel := context.WithTimeout(context.Background(), keyCleanupTimeout)
	defer cancel()
	d.cleanupSSHKey(ctx, api)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Millisecond
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
