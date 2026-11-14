package cloudblast

import (
	"strconv"
	"strings"
	"testing"

	"github.com/docker/machine/libmachine/state"
)

type fakeOptions map[string]any

func (f fakeOptions) String(key string) string {
	v, _ := f[key].(string)
	return v
}

func (f fakeOptions) StringSlice(key string) []string {
	v, _ := f[key].([]string)
	return v
}

func (f fakeOptions) Int(key string) int {
	switch v := f[key].(type) {
	case int:
		return v
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

func (f fakeOptions) Bool(key string) bool {
	v, _ := f[key].(bool)
	return v
}

var cloudblastEnv = []string{
	"CLOUDBLAST_API_TOKEN", "CLOUDBLAST_API_URL", "CLOUDBLAST_INSECURE",
	"CLOUDBLAST_LOCATION_ID", "CLOUDBLAST_PLAN_ID", "CLOUDBLAST_TEMPLATE_SLUG",
	"CLOUDBLAST_POST_BOOT_SCRIPT", "CLOUDBLAST_SSH_USER", "CLOUDBLAST_SSH_PORT",
	"CLOUDBLAST_WAIT_TIMEOUT", "CLOUDBLAST_KEEP_IPS", "CLOUDBLAST_HOSTNAME_PREFIX",
}

func clearCloudblastEnv(t *testing.T) {
	t.Helper()
	for _, key := range cloudblastEnv {
		t.Setenv(key, "")
	}
}

func TestSetConfigFromFlagsDefaults(t *testing.T) {
	clearCloudblastEnv(t)
	d := NewDriver("machine-1", t.TempDir())
	if err := d.SetConfigFromFlags(fakeOptions{}); err != nil {
		t.Fatalf("SetConfigFromFlags: %v", err)
	}
	if d.APIBaseURL != DefaultAPIBaseURL {
		t.Fatalf("base url = %q", d.APIBaseURL)
	}
	if d.SSHUser != "root" || d.SSHPort != 22 {
		t.Fatalf("ssh = %s:%d", d.SSHUser, d.SSHPort)
	}
	if d.WaitTimeoutSecs != 600 {
		t.Fatalf("timeout = %d", d.WaitTimeoutSecs)
	}
	if d.HostnamePrefix != "cb-" {
		t.Fatalf("prefix = %q", d.HostnamePrefix)
	}
	if d.KeepIPs {
		t.Fatal("keep-ips default must be false")
	}
}

func TestSetConfigFromFlagsEnvFallback(t *testing.T) {
	clearCloudblastEnv(t)
	t.Setenv("CLOUDBLAST_API_TOKEN", "env-token")
	t.Setenv("CLOUDBLAST_LOCATION_ID", "5")
	t.Setenv("CLOUDBLAST_PLAN_ID", "19")
	t.Setenv("CLOUDBLAST_TEMPLATE_SLUG", "ubuntu-24.04")
	t.Setenv("CLOUDBLAST_POST_BOOT_SCRIPT", "echo post-boot")
	t.Setenv("CLOUDBLAST_WAIT_TIMEOUT", "900")
	t.Setenv("CLOUDBLAST_KEEP_IPS", "true")
	t.Setenv("CLOUDBLAST_HOSTNAME_PREFIX", "env-")

	d := NewDriver("m", t.TempDir())
	if err := d.SetConfigFromFlags(fakeOptions{}); err != nil {
		t.Fatalf("SetConfigFromFlags: %v", err)
	}
	if d.Token != "env-token" || d.LocationID != 5 || d.PlanID != 19 {
		t.Fatalf("env values not applied: %+v", d)
	}
	if d.TemplateSlug != "ubuntu-24.04" || d.WaitTimeoutSecs != 900 {
		t.Fatalf("env values not applied: %+v", d)
	}
	if d.PostBootScript != "echo post-boot" {
		t.Fatalf("post-boot script = %q", d.PostBootScript)
	}
	if !d.KeepIPs || d.HostnamePrefix != "env-" {
		t.Fatalf("env bool/string not applied: %+v", d)
	}
}

func TestSetConfigFromFlagsInvalidEnvInt(t *testing.T) {
	clearCloudblastEnv(t)
	t.Setenv("CLOUDBLAST_PLAN_ID", "not-a-number")
	d := NewDriver("m", t.TempDir())
	if err := d.SetConfigFromFlags(fakeOptions{}); err == nil {
		t.Fatal("expected error for invalid env int")
	}
}

func TestCreateFlagsContract(t *testing.T) {
	d := NewDriver("m", t.TempDir())
	required := []string{
		"cloudblast-token", "cloudblast-base-url", "cloudblast-insecure",
		"cloudblast-location-id", "cloudblast-plan-id", "cloudblast-template-slug",
		"cloudblast-post-boot-script", "cloudblast-ssh-user", "cloudblast-ssh-port",
		"cloudblast-wait-timeout", "cloudblast-keep-ips", "cloudblast-hostname-prefix",
	}
	forbidden := []string{"user-data", "userdata", "custom-data", "cloud-config"}
	have := map[string]bool{}
	for _, f := range d.GetCreateFlags() {
		name := f.String()
		have[name] = true
		lower := strings.ToLower(name)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("flag %q must not match Rancher user-data detection (%q)", name, bad)
			}
		}
	}
	for _, name := range required {
		if !have[name] {
			t.Errorf("missing flag %q", name)
		}
	}
}

func TestPreCreateCheck(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Driver)
		wantErr string
	}{
		{name: "valid", mutate: func(*Driver) {}},
		{name: "no token", mutate: func(d *Driver) { d.Token = "" }, wantErr: "cloudblast-token is required"},
		{name: "no location", mutate: func(d *Driver) { d.LocationID = 0 }, wantErr: "cloudblast-location-id must be > 0"},
		{name: "no plan", mutate: func(d *Driver) { d.PlanID = 0 }, wantErr: "cloudblast-plan-id must be > 0"},
		{name: "no template", mutate: func(d *Driver) { d.TemplateSlug = "" }, wantErr: "cloudblast-template-slug is required"},
		{name: "timeout too small", mutate: func(d *Driver) { d.WaitTimeoutSecs = 30 }, wantErr: "between 60 and 3600"},
		{name: "timeout too big", mutate: func(d *Driver) { d.WaitTimeoutSecs = 3601 }, wantErr: "between 60 and 3600"},
		{name: "bad base url", mutate: func(d *Driver) { d.APIBaseURL = "console.cloudblast.io" }, wantErr: "invalid cloudblast-base-url"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearCloudblastEnv(t)
			d := NewDriver("machine-1", t.TempDir())
			d.Token = "token"
			d.LocationID = 5
			d.PlanID = 19
			d.TemplateSlug = "ubuntu-24.04"
			d.WaitTimeoutSecs = 600
			tc.mutate(d)

			err := d.PreCreateCheck()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestDriverNameAndCachedAddress(t *testing.T) {
	d := NewDriver("m", t.TempDir())
	if d.DriverName() != "cloudblast" {
		t.Fatalf("DriverName = %q", d.DriverName())
	}
	if _, err := d.GetIP(); err == nil {
		t.Fatal("GetIP without a server must fail")
	}
	d.BaseDriver.IPAddress = "203.0.113.10"
	url, err := d.GetURL()
	if err != nil || url != "tcp://203.0.113.10:2376" {
		t.Fatalf("GetURL = %q, %v", url, err)
	}
	got, err := d.GetState()
	if err != nil || got != state.None {
		t.Fatalf("GetState without server = %v, %v; want None", got, err)
	}
}
