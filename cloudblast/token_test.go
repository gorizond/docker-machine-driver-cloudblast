package cloudblast

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/docker/machine/libmachine/log"
)

const testTokenValue = "cb_live_persisted_secret_value"

func TestTokenPersistedInStateButMaskedInLogs(t *testing.T) {
	d := NewDriver("machine-1", t.TempDir())
	d.Token = testTokenValue
	d.PostBootScript = "curl -H 'X-Secret: script-secret-content'"

	state, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal driver state: %v", err)
	}
	if !strings.Contains(string(state), `"token":"`+testTokenValue+`"`) {
		t.Fatalf("persisted state does not contain token field: %s", state)
	}
	if strings.Contains(string(state), "script-secret-content") {
		t.Fatalf("post-boot script content must not be persisted: %s", state)
	}

	if masked := d.maskDriverSecrets("token=" + testTokenValue + " CATTLE_TOKEN=cattle-secret-value"); strings.Contains(masked, testTokenValue) || strings.Contains(masked, "cattle-secret-value") {
		t.Fatalf("maskDriverSecrets leaked a secret: %q", masked)
	}

	var buf bytes.Buffer
	log.SetOutWriter(&buf)
	defer log.SetOutWriter(os.Stdout)
	d.logf("auth token=%s CATTLE_TOKEN=cattle-secret-value", d.Token)

	if strings.Contains(buf.String(), testTokenValue) {
		t.Fatalf("logf leaked the API token: %q", buf.String())
	}
	if strings.Contains(buf.String(), "cattle-secret-value") {
		t.Fatalf("logf leaked CATTLE_TOKEN: %q", buf.String())
	}
}
