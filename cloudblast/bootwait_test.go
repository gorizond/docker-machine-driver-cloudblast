package cloudblast

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCreateWaitsForBootFinishedWithoutScript(t *testing.T) {
	transport := &fakeTransport{route: readyAPI}
	d := newUS1Driver(t, transport)
	d.WaitBootFinished = true
	d.BootFinishedTimeoutSecs = 60

	probes := 0
	fake := &SSHClient{runFunc: func(_ context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "boot-finished") {
			probes++
			if probes < 3 {
				return "no", nil
			}
			return "yes", nil
		}
		return "", nil
	}}
	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) { return fake, nil }

	if err := d.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if probes != 3 {
		t.Fatalf("boot-finished probes = %d, want 3", probes)
	}
}

func TestWaitForBootFinishedMarkerPresentIsFast(t *testing.T) {
	d := newPostBootTestDriver(t)
	probes := 0
	fake := &SSHClient{runFunc: func(_ context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "boot-finished") {
			probes++
			return "yes", nil
		}
		return "", nil
	}}
	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) { return fake, nil }

	if ok := d.waitForBootFinished("fake", time.Second); !ok {
		t.Fatal("expected boot-finished success")
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want 1", probes)
	}
}

func TestWaitForBootFinishedTimeoutWarnsAndReturns(t *testing.T) {
	d := newPostBootTestDriver(t)
	fake := &SSHClient{runFunc: func(_ context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "boot-finished") {
			return "no", nil
		}
		return "", nil
	}}
	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) { return fake, nil }

	if ok := d.waitForBootFinished("fake", 30*time.Millisecond); ok {
		t.Fatal("expected timeout without marker")
	}
}

func TestCreatePostBootScriptWithWaitTrueSkipsDuplicateProbe(t *testing.T) {
	transport := &fakeTransport{route: readyAPI}
	d := newUS1Driver(t, transport)
	d.WaitBootFinished = true
	d.BootFinishedTimeoutSecs = 60
	d.PostBootScript = "echo hi"

	waitClient := &fakePostBootClient{}
	waitClient.runFunc = waitClient.run
	scriptClient := &fakePostBootClient{}
	scriptClient.runFunc = scriptClient.run

	restore := waitForSSHFunc
	defer func() { waitForSSHFunc = restore }()
	connects := 0
	waitForSSHFunc = func(context.Context, SSHConfig) (*SSHClient, error) {
		connects++
		if connects == 1 {
			return waitClient.ssh(), nil
		}
		return scriptClient.ssh(), nil
	}

	if err := d.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if connects != 2 {
		t.Fatalf("SSH connects = %d, want 2 (wait + script)", connects)
	}
	if scriptClient.probes != 0 {
		t.Fatalf("post-boot phase repeated the boot-finished probe %d time(s)", scriptClient.probes)
	}
	if scriptClient.uploads != 1 {
		t.Fatalf("uploads = %d, want 1", scriptClient.uploads)
	}
}
