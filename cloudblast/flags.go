package cloudblast

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/mcnflag"
)

// GetCreateFlags registers the driver flags. The "cloudblast-user-data" flag is
// mandatory for Rancher: it detects the substring "user-data" and from then on
// merges install.sh into the cloud-config delivered by this driver.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "cloudblast-token",
			Usage:  "CloudBlast API token (Bearer)",
			EnvVar: "CLOUDBLAST_API_TOKEN",
		},
		mcnflag.StringFlag{
			Name:   "cloudblast-base-url",
			Usage:  "CloudBlast API base URL",
			EnvVar: "CLOUDBLAST_API_URL",
			Value:  DefaultAPIBaseURL,
		},
		mcnflag.BoolFlag{
			Name:   "cloudblast-insecure",
			Usage:  "Skip TLS verification (test installations only)",
			EnvVar: "CLOUDBLAST_INSECURE",
		},
		mcnflag.IntFlag{
			Name:   "cloudblast-location-id",
			Usage:  "CloudBlast location id",
			EnvVar: "CLOUDBLAST_LOCATION_ID",
		},
		mcnflag.IntFlag{
			Name:   "cloudblast-plan-id",
			Usage:  "CloudBlast plan (flavor) id",
			EnvVar: "CLOUDBLAST_PLAN_ID",
		},
		mcnflag.StringFlag{
			Name:   "cloudblast-template-slug",
			Usage:  "CloudBlast OS template slug (e.g. ubuntu-24.04)",
			EnvVar: "CLOUDBLAST_TEMPLATE_SLUG",
		},
		mcnflag.StringFlag{
			Name:   "cloudblast-user-data",
			Usage:  "Path to merged cloud-config or inline cloud-config",
			EnvVar: "CLOUDBLAST_USER_DATA",
		},
		mcnflag.StringFlag{
			Name:   "cloudblast-ssh-user",
			Usage:  "SSH user",
			EnvVar: "CLOUDBLAST_SSH_USER",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			Name:   "cloudblast-ssh-port",
			Usage:  "SSH port",
			EnvVar: "CLOUDBLAST_SSH_PORT",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			Name:   "cloudblast-wait-timeout",
			Usage:  "Server readiness timeout in seconds (60-3600)",
			EnvVar: "CLOUDBLAST_WAIT_TIMEOUT",
			Value:  defaultWaitTimeoutSecs,
		},
		mcnflag.BoolFlag{
			Name:   "cloudblast-keep-ips",
			Usage:  "Keep reserved IP addresses when the server is deleted",
			EnvVar: "CLOUDBLAST_KEEP_IPS",
		},
		mcnflag.StringFlag{
			Name:   "cloudblast-hostname-prefix",
			Usage:  "Prefix for the CloudBlast hostname used for reconcile",
			EnvVar: "CLOUDBLAST_HOSTNAME_PREFIX",
			Value:  defaultHostnamePrefix,
		},
	}
}

// SetConfigFromFlags reads driver flags. Environment variables act as a
// fallback because DriverOptions cannot distinguish "unset" from "zero".
func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {
	d.Token = stringOpt(opts, "cloudblast-token", "CLOUDBLAST_API_TOKEN", "")
	d.APIBaseURL = stringOpt(opts, "cloudblast-base-url", "CLOUDBLAST_API_URL", DefaultAPIBaseURL)
	d.APIInsecure = boolOpt(opts, "cloudblast-insecure", "CLOUDBLAST_INSECURE")
	d.TemplateSlug = stringOpt(opts, "cloudblast-template-slug", "CLOUDBLAST_TEMPLATE_SLUG", "")
	d.UserDataFlag = stringOpt(opts, "cloudblast-user-data", "CLOUDBLAST_USER_DATA", "")
	d.HostnamePrefix = stringOpt(opts, "cloudblast-hostname-prefix", "CLOUDBLAST_HOSTNAME_PREFIX", defaultHostnamePrefix)
	d.KeepIPs = boolOpt(opts, "cloudblast-keep-ips", "CLOUDBLAST_KEEP_IPS")
	d.SSHUser = stringOpt(opts, "cloudblast-ssh-user", "CLOUDBLAST_SSH_USER", defaultSSHUser)

	var err error
	if d.LocationID, err = intOpt(opts, "cloudblast-location-id", "CLOUDBLAST_LOCATION_ID", 0); err != nil {
		return err
	}
	if d.PlanID, err = intOpt(opts, "cloudblast-plan-id", "CLOUDBLAST_PLAN_ID", 0); err != nil {
		return err
	}
	if d.SSHPort, err = intOpt(opts, "cloudblast-ssh-port", "CLOUDBLAST_SSH_PORT", defaultSSHPort); err != nil {
		return err
	}
	if d.WaitTimeoutSecs, err = intOpt(opts, "cloudblast-wait-timeout", "CLOUDBLAST_WAIT_TIMEOUT", defaultWaitTimeoutSecs); err != nil {
		return err
	}

	d.SetSwarmConfigFromFlags(opts)
	return nil
}

func stringOpt(opts drivers.DriverOptions, name, env, def string) string {
	if v := strings.TrimSpace(opts.String(name)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	return def
}

// intOpt treats 0 as "unset" (all int flags in this driver are positive).
func intOpt(opts drivers.DriverOptions, name, env string, def int) (int, error) {
	if v := opts.Int(name); v != 0 {
		return v, nil
	}
	if raw := strings.TrimSpace(os.Getenv(env)); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid %s: %q is not an integer", env, raw)
		}
		return v, nil
	}
	return def, nil
}

func boolOpt(opts drivers.DriverOptions, name, env string) bool {
	if opts.Bool(name) {
		return true
	}
	if raw := strings.TrimSpace(os.Getenv(env)); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			return v
		}
	}
	return false
}

func validateWaitTimeout(seconds int) error {
	if seconds < minWaitTimeoutSecs || seconds > maxWaitTimeoutSecs {
		return fmt.Errorf("cloudblast-wait-timeout must be between %d and %d seconds", minWaitTimeoutSecs, maxWaitTimeoutSecs)
	}
	return nil
}

func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid cloudblast-base-url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid cloudblast-base-url: scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("invalid cloudblast-base-url: host is missing")
	}
	return nil
}
