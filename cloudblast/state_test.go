package cloudblast

import (
	"strings"
	"testing"

	"github.com/docker/machine/libmachine/state"
)

func TestMapState(t *testing.T) {
	str := func(v string) *string { return &v }

	cases := []struct {
		name       string
		hypervisor string
		app        *string
		want       state.State
		wantErr    bool
		errText    string
	}{
		{name: "absent", hypervisor: "", app: nil, want: state.None},
		{name: "installing app", hypervisor: "running", app: str("installing"), want: state.Starting},
		{name: "running", hypervisor: "running", app: nil, want: state.Running},
		{name: "stopped", hypervisor: "stopped", app: nil, want: state.Stopped},
		{name: "shutting down", hypervisor: "shutting_down", app: nil, want: state.Stopping},
		{name: "suspended app", hypervisor: "running", app: str("suspended"), want: state.Stopped},
		{name: "deleting", hypervisor: "running", app: str("deleting"), want: state.Stopping},
		{name: "restoring backup", hypervisor: "running", app: str("restoring_backup"), want: state.Starting},
		{name: "install failed", hypervisor: "running", app: str("install_failed"), want: state.Error, wantErr: true, errText: "install_failed"},
		{name: "deletion failed", hypervisor: "running", app: str("deletion_failed"), want: state.Error, wantErr: true, errText: "deletion_failed"},
		{name: "unknown app", hypervisor: "running", app: str("mystery"), want: state.Error, wantErr: true, errText: "mystery"},
		{name: "unknown hypervisor", hypervisor: "paused", app: nil, want: state.Error, wantErr: true, errText: "paused"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MapState(tc.hypervisor, tc.app)
			if got != tc.want {
				t.Fatalf("state = %v, want %v", got, tc.want)
			}
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.errText != "" && !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("error %q does not contain %q", err, tc.errText)
			}
		})
	}
}
