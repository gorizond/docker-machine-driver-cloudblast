package cloudblast

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func withCloudInitPoll(t *testing.T) {
	t.Helper()
	old := cloudInitPollInterval
	cloudInitPollInterval = time.Millisecond
	t.Cleanup(func() { cloudInitPollInterval = old })
}

func fakeSSHRunner(run func(cmd string) (string, error)) *SSHClient {
	return &SSHClient{runFunc: func(_ context.Context, cmd string) (string, error) {
		return run(cmd)
	}}
}

func TestWaitCloudInitPollsRunningUntilDone(t *testing.T) {
	withCloudInitPoll(t)
	statusCalls := 0
	client := fakeSSHRunner(func(cmd string) (string, error) {
		switch cmd {
		case cloudInitBootFinishedCmd:
			return "no", nil
		case cloudInitStatusCmd:
			statusCalls++
			if statusCalls == 1 {
				return `{"status":"running"}`, nil
			}
			return `{"status":"done","errors":[]}`, nil
		default:
			return "", errors.New("unexpected command " + cmd)
		}
	})

	if err := client.WaitCloudInit(context.Background(), SSHConfig{Host: "fake"}, 2*time.Second, nil); err != nil {
		t.Fatalf("WaitCloudInit: %v", err)
	}
	if statusCalls != 2 {
		t.Fatalf("status polls = %d, want 2", statusCalls)
	}
}

func TestWaitCloudInitFailsOnErrorStatus(t *testing.T) {
	withCloudInitPoll(t)
	client := fakeSSHRunner(func(cmd string) (string, error) {
		if cmd == cloudInitBootFinishedCmd {
			return "no", nil
		}
		return `{"status":"error","errors":["apt lock timeout"]}`, nil
	})

	err := client.WaitCloudInit(context.Background(), SSHConfig{Host: "fake"}, time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "cloud-init finished with error") || !strings.Contains(err.Error(), "apt lock timeout") {
		t.Fatalf("error = %v, want clear error status", err)
	}
}

func TestWaitCloudInitReconnectsAfterDroppedSession(t *testing.T) {
	withCloudInitPoll(t)
	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()

	initialStatusCalls := 0
	initial := fakeSSHRunner(func(cmd string) (string, error) {
		if cmd == cloudInitBootFinishedCmd {
			return "no", nil
		}
		initialStatusCalls++
		return "", errors.New("wait: remote command exited without exit status or exit signal")
	})

	reconnects := 0
	reconnectedStatusCalls := 0
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		reconnects++
		return fakeSSHRunner(func(cmd string) (string, error) {
			if cmd == cloudInitBootFinishedCmd {
				return "no", nil
			}
			reconnectedStatusCalls++
			if reconnectedStatusCalls == 1 {
				return `{"status":"running"}`, nil
			}
			return `{"status":"done"}`, nil
		}), nil
	}

	if err := initial.WaitCloudInit(context.Background(), SSHConfig{Host: "fake"}, time.Second, nil); err != nil {
		t.Fatalf("WaitCloudInit: %v", err)
	}
	if reconnects != 1 {
		t.Fatalf("reconnects = %d, want 1", reconnects)
	}
	if initialStatusCalls != 1 || reconnectedStatusCalls != 2 {
		t.Fatalf("status calls initial=%d reconnected=%d, want 1/2", initialStatusCalls, reconnectedStatusCalls)
	}
}

func TestWaitCloudInitBootFinishedShortcut(t *testing.T) {
	withCloudInitPoll(t)
	statusCalls := 0
	client := fakeSSHRunner(func(cmd string) (string, error) {
		if cmd == cloudInitBootFinishedCmd {
			return "yes", nil
		}
		statusCalls++
		return `{"status":"running"}`, nil
	})

	if err := client.WaitCloudInit(context.Background(), SSHConfig{Host: "fake"}, time.Second, nil); err != nil {
		t.Fatalf("WaitCloudInit: %v", err)
	}
	if statusCalls != 0 {
		t.Fatalf("status was polled %d times despite boot-finished marker", statusCalls)
	}
}

func TestWaitCloudInitTimeoutReportsLastStatus(t *testing.T) {
	withCloudInitPoll(t)
	client := fakeSSHRunner(func(cmd string) (string, error) {
		if cmd == cloudInitBootFinishedCmd {
			return "no", nil
		}
		return `{"status":"running"}`, nil
	})

	err := client.WaitCloudInit(context.Background(), SSHConfig{Host: "fake"}, 30*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "did not finish within") || !strings.Contains(err.Error(), `last_status="running"`) {
		t.Fatalf("error = %v, want timeout with last status", err)
	}
}
