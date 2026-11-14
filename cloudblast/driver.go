package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/state"
)

const (
	// DriverName is the Rancher driver id (also the --driver value).
	DriverName = "cloudblast"

	defaultSSHUser         = drivers.DefaultSSHUser
	defaultSSHPort         = drivers.DefaultSSHPort
	defaultWaitTimeoutSecs = 600
	minWaitTimeoutSecs     = 60
	maxWaitTimeoutSecs     = 3600
	defaultHostnamePrefix  = "cb-"

	defaultPollInterval     = 5 * time.Second
	compensationTimeout     = 3 * time.Minute
	removalTimeout          = 5 * time.Minute
	apiOperationTimeout     = 2 * time.Minute
	keyCleanupTimeout       = 30 * time.Second
	sshHandshakeMinTimeout  = 10 * time.Minute
	postBootScriptTimeout   = 10 * time.Minute
	bootFinishedWaitTimeout = 5 * time.Minute
)

// Driver is the CloudBlast node driver state. Fields are persisted in the
// docker-machine store; Token and PostBootScript (which may contain secrets)
// are deliberately not persisted.
type Driver struct {
	*drivers.BaseDriver

	Token          string `json:"-"`
	PostBootScript string `json:"-"`

	APIBaseURL   string `json:"apiBaseUrl,omitempty"`
	APIInsecure  bool   `json:"apiInsecure,omitempty"`
	LocationID   int    `json:"locationId,omitempty"`
	PlanID       int    `json:"planId,omitempty"`
	TemplateSlug string `json:"templateSlug,omitempty"`

	VMUUID            string `json:"vmUuid,omitempty"`
	SSHKeyID          int    `json:"sshKeyId,omitempty"`
	SSHKeyFingerprint string `json:"sshKeyFingerprint,omitempty"`
	WaitTimeoutSecs   int    `json:"waitTimeoutSecs,omitempty"`
	KeepIPs           bool   `json:"keepIps,omitempty"`
	HostnamePrefix    string `json:"hostnamePrefix,omitempty"`

	// test seams; never persisted
	httpClient   *http.Client  `json:"-"`
	pollInterval time.Duration `json:"-"`
}

var _ drivers.Driver = (*Driver)(nil)

// NewDriver creates a driver with CloudBlast defaults.
func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
		},
		APIBaseURL:      DefaultAPIBaseURL,
		WaitTimeoutSecs: defaultWaitTimeoutSecs,
		HostnamePrefix:  defaultHostnamePrefix,
	}
}

// DriverName returns the driver id.
func (d *Driver) DriverName() string {
	return DriverName
}

// PreCreateCheck validates configuration before any CloudBlast call.
func (d *Driver) PreCreateCheck() error {
	if d.BaseDriver == nil {
		d.BaseDriver = &drivers.BaseDriver{}
	}
	if strings.TrimSpace(d.Token) == "" {
		return errors.New("cloudblast-token is required")
	}
	if d.LocationID <= 0 {
		return errors.New("cloudblast-location-id must be > 0")
	}
	if d.PlanID <= 0 {
		return errors.New("cloudblast-plan-id must be > 0")
	}
	if strings.TrimSpace(d.TemplateSlug) == "" {
		return errors.New("cloudblast-template-slug is required")
	}
	if err := validateWaitTimeout(d.WaitTimeoutSecs); err != nil {
		return err
	}
	if err := validateBaseURL(d.APIBaseURL); err != nil {
		return err
	}
	return nil
}

// GetSSHHostname returns the address used by docker-machine for SSH.
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetIP returns the server IPv4 address from credentials.ipv4.
func (d *Driver) GetIP() (string, error) {
	if d.BaseDriver != nil && strings.TrimSpace(d.BaseDriver.IPAddress) != "" {
		return d.BaseDriver.IPAddress, nil
	}
	if strings.TrimSpace(d.VMUUID) == "" {
		return "", errors.New("cloudblast: machine has no server yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiOperationTimeout)
	defer cancel()

	creds, err := d.newClient().GetServerCredentials(ctx, d.VMUUID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(creds.IPv4) == "" {
		return "", fmt.Errorf("cloudblast: server %s has no IPv4 address: IPv6-only is not supported", d.VMUUID)
	}
	d.BaseDriver.IPAddress = creds.IPv4
	return creds.IPv4, nil
}

// GetURL returns a Docker-compatible URL.
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil
}

// GetState maps the CloudBlast status endpoint to a docker-machine state.
func (d *Driver) GetState() (state.State, error) {
	if strings.TrimSpace(d.VMUUID) == "" {
		return state.None, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiOperationTimeout)
	defer cancel()

	st, err := d.newClient().GetServerStatus(ctx, d.VMUUID)
	if err != nil {
		if IsNotFound(err) {
			return state.None, nil
		}
		return state.Error, err
	}
	return MapState(st.State, st.ServerStatus)
}

// Start powers the server on.
func (d *Driver) Start() error { return d.powerAction("start", false) }

// Stop gracefully shuts the server down.
func (d *Driver) Stop() error { return d.powerAction("shutdown", true) }

// Restart reboots the server.
func (d *Driver) Restart() error { return d.powerAction("restart", false) }

// Kill forcefully stops the server (not an alias for Stop).
func (d *Driver) Kill() error { return d.powerAction("kill", true) }

func (d *Driver) powerAction(action string, missingOK bool) error {
	if strings.TrimSpace(d.VMUUID) == "" {
		if missingOK {
			return nil
		}
		return errors.New("cloudblast: machine has no server yet")
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiOperationTimeout)
	defer cancel()

	err := d.newClient().ServerAction(ctx, d.VMUUID, action)
	if err != nil && missingOK && IsNotFound(err) {
		return nil
	}
	return err
}

// newClient builds an API client, using the test HTTP client when injected.
func (d *Driver) newClient() *Client {
	client := NewClient(d.APIBaseURL, d.Token, d.APIInsecure)
	if d.httpClient != nil {
		client.HTTPClient = d.httpClient
	}
	return client
}

func (d *Driver) pollEvery() time.Duration {
	if d.pollInterval > 0 {
		return d.pollInterval
	}
	return defaultPollInterval
}

func (d *Driver) readyTimeout() time.Duration {
	seconds := d.WaitTimeoutSecs
	if seconds <= 0 {
		seconds = defaultWaitTimeoutSecs
	}
	return time.Duration(seconds) * time.Second
}
