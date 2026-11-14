package cloudblast

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Remove deletes the server, waits until it is gone and best-effort removes the
// SSH key when no other server uses it. A missing server is success.
func (d *Driver) Remove() error {
	if strings.TrimSpace(d.VMUUID) == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), removalTimeout)
	defer cancel()
	api := d.newClient()

	if err := api.DeleteServer(ctx, d.VMUUID, d.KeepIPs); err != nil {
		return err
	}
	if err := d.waitServerGone(ctx, api, d.VMUUID); err != nil {
		return err
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), keyCleanupTimeout)
	defer cleanupCancel()
	d.cleanupSSHKey(cleanupCtx, api)

	d.VMUUID = ""
	d.SSHKeyID = 0
	d.SSHKeyFingerprint = ""
	if d.BaseDriver != nil {
		d.BaseDriver.IPAddress = ""
	}
	return nil
}

func (d *Driver) waitServerGone(ctx context.Context, api *Client, uuid string) error {
	deadline := time.Now().Add(removalTimeout)
	for {
		server, err := api.GetServer(ctx, uuid)
		if err != nil {
			if IsNotFound(err) {
				return nil
			}
			return err
		}
		if server.Status != nil && *server.Status == "deletion_failed" {
			return fmt.Errorf("cloudblast: server %s failed to delete (status=%q)", uuid, *server.Status)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cloudblast: server %s was not deleted within %s", uuid, removalTimeout)
		}
		if err := sleepCtx(ctx, d.pollEvery()); err != nil {
			return fmt.Errorf("cloudblast: waiting for server %s deletion: %w", uuid, err)
		}
	}
}

// cleanupSSHKey deletes the registered key only when no other server uses it.
// On uncertainty (listing failed) the key is kept and the reason is logged.
func (d *Driver) cleanupSSHKey(ctx context.Context, api *Client) {
	if d.SSHKeyID == 0 {
		return
	}
	servers, err := api.ListServers(ctx)
	if err != nil {
		d.logf("keeping SSH key id=%d: cannot verify usage: %v", d.SSHKeyID, err)
		return
	}
	for _, server := range servers {
		if server.UUID == d.VMUUID {
			continue
		}
		for _, keyID := range server.SSHKeyIDs {
			if keyID == d.SSHKeyID {
				d.debugf("keeping SSH key id=%d: used by server %s", d.SSHKeyID, server.UUID)
				return
			}
		}
	}
	if err := api.DeleteSSHKey(ctx, d.SSHKeyID); err != nil && !IsNotFound(err) {
		d.logf("best-effort delete of SSH key id=%d failed: %v", d.SSHKeyID, err)
		return
	}
	d.SSHKeyID = 0
}
