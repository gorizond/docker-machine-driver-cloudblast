package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	instanceCloudConfig = "/var/lib/cloud/instance/cloud-config.txt"
	cloudConfigBackup   = instanceCloudConfig + ".cloudblast-backup"
)

// Runner executes commands and writes files on the target node. SSHClient is
// the production implementation; tests can substitute a fake.
type Runner interface {
	Run(ctx context.Context, cmd string) (string, error)
	WriteFile(ctx context.Context, path string, content []byte, perm os.FileMode) error
}

// CloudInitModules returns the ordered cloud-init single modules needed for the
// supported subset. bootcmd/write_files/hostname/runcmd are always applied;
// package installation and user management only when the config asks for them.
func CloudInitModules(ud *UserData) []string {
	modules := []string{
		"cc_bootcmd",
		"cc_write_files",
		"cc_set_hostname",
	}
	if ud.HasPackages() {
		modules = append(modules, "cc_package_update_upgrade_install")
	}
	modules = append(modules, "cc_write_files_deferred")
	if ud.HasUsers() {
		modules = append(modules, "cc_users_groups")
	}
	modules = append(modules, "cc_runcmd", "cc_scripts_user")
	return modules
}

// ApplyCloudConfig applies merged cloud-config on a running node. It backs up
// the provider's cloud-config, writes the merged file, runs the given modules
// sequentially and always restores the backup. It never runs
// "cloud-init clean" or "cloud-init init" (they break networking).
func ApplyCloudConfig(ctx context.Context, r Runner, userDataPath string, modules []string) (applied []string, err error) {
	if r == nil {
		return nil, errors.New("cloudblast: cloud-init runner is required")
	}
	content, err := os.ReadFile(userDataPath)
	if err != nil {
		return nil, fmt.Errorf("cloudblast: read merged user-data: %w", err)
	}

	if _, err := r.Run(ctx, "cp -a "+shellQuote(instanceCloudConfig)+" "+shellQuote(cloudConfigBackup)); err != nil {
		return nil, fmt.Errorf("cloudblast: backup cloud-config: %s", maskSecrets(err.Error()))
	}
	backupMade := true
	defer func() {
		if !backupMade {
			return
		}
		restoreErr := restoreCloudConfig(ctx, r)
		if restoreErr == nil {
			return
		}
		if err == nil {
			err = restoreErr
		} else {
			err = fmt.Errorf("%w (restore failed: %v)", err, restoreErr)
		}
	}()

	if err := r.WriteFile(ctx, instanceCloudConfig, content, 0o600); err != nil {
		return applied, fmt.Errorf("cloudblast: write merged cloud-config: %s", maskSecrets(err.Error()))
	}

	for _, module := range modules {
		cmd := "cloud-init single --name " + module + " --frequency always"
		if _, runErr := r.Run(ctx, cmd); runErr != nil {
			return applied, fmt.Errorf("cloudblast: cloud-init module %s failed after %v: %s", module, applied, maskSecrets(runErr.Error()))
		}
		applied = append(applied, module)
	}
	return applied, nil
}

func restoreCloudConfig(ctx context.Context, r Runner) error {
	cmd := "cp -a " + shellQuote(cloudConfigBackup) + " " + shellQuote(instanceCloudConfig) +
		" && rm -f " + shellQuote(cloudConfigBackup)
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("cloudblast: restore cloud-config: %s", maskSecrets(err.Error()))
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
