package cloudblast

import (
	"errors"
	"fmt"
	"strings"

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
)

// ErrPhase2NotImplemented marks lifecycle methods delivered by US1/US3.
var ErrPhase2NotImplemented = errors.New("cloudblast: not implemented in phase 2")

// Driver is the CloudBlast node driver state. Fields are persisted in the
// docker-machine store; Token and UserDataFlag are deliberately not persisted.
type Driver struct {
	*drivers.BaseDriver

	Token        string `json:"-"`
	UserDataFlag string `json:"-"`

	APIBaseURL   string `json:"apiBaseUrl,omitempty"`
	APIInsecure  bool   `json:"apiInsecure,omitempty"`
	LocationID   int    `json:"locationId,omitempty"`
	PlanID       int    `json:"planId,omitempty"`
	TemplateSlug string `json:"templateSlug,omitempty"`

	VMUUID            string   `json:"vmUuid,omitempty"`
	SSHKeyID          int      `json:"sshKeyId,omitempty"`
	SSHKeyFingerprint string   `json:"sshKeyFingerprint,omitempty"`
	UserDataSHA256    string   `json:"userDataSha256,omitempty"`
	UserDataTmpPath   string   `json:"userDataTmpPath,omitempty"`
	AppliedModules    []string `json:"appliedModules,omitempty"`
	WaitTimeoutSecs   int      `json:"waitTimeoutSecs,omitempty"`
	KeepIPs           bool     `json:"keepIps,omitempty"`
	HostnamePrefix    string   `json:"hostnamePrefix,omitempty"`
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
	if strings.TrimSpace(d.UserDataFlag) == "" {
		return errors.New("cloudblast-user-data is required")
	}
	ud, err := LoadUserData(d.UserDataFlag)
	if err != nil {
		return err
	}
	d.logUserDataSummary(ud)
	return ud.Cleanup()
}

// GetSSHHostname returns the address used by docker-machine for SSH.
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetIP returns the cached server IPv4 address.
func (d *Driver) GetIP() (string, error) {
	if d.BaseDriver != nil && strings.TrimSpace(d.BaseDriver.IPAddress) != "" {
		return d.BaseDriver.IPAddress, nil
	}
	return "", notImplemented("GetIP")
}

// GetURL returns a Docker-compatible URL.
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil
}

// Create is implemented in US1 (T023-T028).
func (d *Driver) Create() error { return notImplemented("Create") }

// Remove is implemented in US1 (T027).
func (d *Driver) Remove() error { return notImplemented("Remove") }

// GetState is implemented in US3 (T040).
func (d *Driver) GetState() (state.State, error) {
	return state.Error, notImplemented("GetState")
}

// Start is implemented in US3 (T039).
func (d *Driver) Start() error { return notImplemented("Start") }

// Stop is implemented in US3 (T039).
func (d *Driver) Stop() error { return notImplemented("Stop") }

// Restart is implemented in US3 (T039).
func (d *Driver) Restart() error { return notImplemented("Restart") }

// Kill is implemented in US3 (T039).
func (d *Driver) Kill() error { return notImplemented("Kill") }

func notImplemented(op string) error {
	return fmt.Errorf("%w: %s", ErrPhase2NotImplemented, op)
}
