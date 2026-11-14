package cloudblast

import (
	"os"
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
	"CLOUDBLAST_USER_DATA", "CLOUDBLAST_SSH_USER", "CLOUDBLAST_SSH_PORT",
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
	t.Setenv("CLOUDBLAST_USER_DATA", "#cloud-config\nruncmd: [echo hi]")
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
		"cloudblast-user-data", "cloudblast-ssh-user", "cloudblast-ssh-port",
		"cloudblast-wait-timeout", "cloudblast-keep-ips", "cloudblast-hostname-prefix",
	}
	have := map[string]bool{}
	userDataFlag := false
	for _, f := range d.GetCreateFlags() {
		have[f.String()] = true
		if strings.Contains(f.String(), "user-data") {
			userDataFlag = true
		}
	}
	for _, name := range required {
		if !have[name] {
			t.Errorf("missing flag %q", name)
		}
	}
	if !userDataFlag {
		t.Fatal(`flag containing "user-data" is required for Rancher merge detection`)
	}
}

func TestPreCreateCheck(t *testing.T) {
	validUserData := func(t *testing.T) string {
		t.Helper()
		path := t.TempDir() + "/cloud-config.yaml"
		content := "#cloud-config\nruncmd:\n  - echo hi\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

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
		{name: "no user data", mutate: func(d *Driver) { d.UserDataFlag = "" }, wantErr: "cloudblast-user-data is required"},
		{name: "rejected user data key", mutate: func(d *Driver) {
			d.UserDataFlag = "#cloud-config\nnetwork: {}\n"
		}, wantErr: `key "network" is not supported`},
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
			d.UserDataFlag = validUserData(t)
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
