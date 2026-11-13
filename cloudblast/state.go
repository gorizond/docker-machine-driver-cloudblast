package cloudblast

import (
	"fmt"
	"strings"

	"github.com/docker/machine/libmachine/state"
)

// MapState converts CloudBlast hypervisor state and application status into a
// docker-machine state. An absent server is represented by an empty hypervisor
// state and a nil application status, and maps to state.None.
func MapState(hypervisorState string, appStatus *string) (state.State, error) {
	if appStatus != nil {
		status := strings.TrimSpace(*appStatus)
		if status != "" {
			switch status {
			case "installing", "restoring_backup", "restoring_snapshot":
				return state.Starting, nil
			case "running":
				return state.Running, nil
			case "stopped", "suspended":
				return state.Stopped, nil
			case "deleting":
				return state.Stopping, nil
			case "deletion_failed", "install_failed":
				return state.Error, fmt.Errorf("cloudblast: server status is %q", status)
			default:
				return state.Error, fmt.Errorf("cloudblast: unknown server status %q", status)
			}
		}
	}

	switch strings.TrimSpace(hypervisorState) {
	case "":
		return state.None, nil
	case "running":
		return state.Running, nil
	case "stopped":
		return state.Stopped, nil
	case "shutting_down":
		return state.Stopping, nil
	case "installing":
		return state.Starting, nil
	case "suspended":
		return state.Stopped, nil
	default:
		return state.Error, fmt.Errorf("cloudblast: unknown server state %q", hypervisorState)
	}
}
