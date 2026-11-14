package cloudblast

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/docker/machine/libmachine/log"
)

var (
	apiTokenRE    = regexp.MustCompile(`cb_live_[A-Za-z0-9._-]+`)
	cattleTokenRE = regexp.MustCompile(`(?i)(CATTLE_TOKEN\s*[=:]\s*)["']?[A-Za-z0-9._+/=-]+`)
	passwordRE    = regexp.MustCompile(`(?i)((?:root_)?password\s*[=:]\s*)["']?[^\s"',}]+`)
)

// logf writes a structured driver log line. It never receives script content.
func (d *Driver) logf(format string, args ...any) {
	log.Infof("%s%s", d.logPrefix(), d.maskDriverSecrets(fmt.Sprintf(format, args...)))
}

func (d *Driver) debugf(format string, args ...any) {
	log.Debugf("%s%s", d.logPrefix(), d.maskDriverSecrets(fmt.Sprintf(format, args...)))
}

func (d *Driver) logPrefix() string {
	fields := d.logFields()
	return fmt.Sprintf("[cloudblast] machine=%s uuid=%s ", fields[0], fields[1])
}

// logFields returns the machine name and uuid as leading format arguments.
func (d *Driver) logFields() []any {
	name, uuid := "-", "-"
	if d.BaseDriver != nil && d.BaseDriver.MachineName != "" {
		name = d.BaseDriver.MachineName
	}
	if d.VMUUID != "" {
		uuid = d.VMUUID
	}
	return []any{name, uuid}
}

// maskSecrets redacts tokens, passwords and CATTLE_TOKEN values from free-form
// text before it reaches logs or errors.
func maskSecrets(s string) string {
	if s == "" {
		return s
	}
	masked := apiTokenRE.ReplaceAllString(s, "cb_live_***")
	masked = cattleTokenRE.ReplaceAllString(masked, "${1}***")
	masked = passwordRE.ReplaceAllString(masked, "${1}***")
	return masked
}

// maskDriverSecrets additionally replaces the configured API token.
func (d *Driver) maskDriverSecrets(s string) string {
	s = maskSecrets(s)
	if d.Token != "" {
		s = strings.ReplaceAll(s, d.Token, "***")
	}
	return s
}
