package cloudblast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPostBootScriptPathAtPathAndInline(t *testing.T) {
	content := "#!/bin/sh\necho post-boot\n"
	path := filepath.Join(t.TempDir(), "post-boot.sh")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{path, "@" + path} {
		got, err := readPostBootScript(value)
		if err != nil {
			t.Fatalf("readPostBootScript(%q): %v", value, err)
		}
		if string(got) != content {
			t.Fatalf("readPostBootScript(%q) = %q", value, got)
		}
	}

	inline := "echo inline script"
	got, err := readPostBootScript(inline)
	if err != nil || string(got) != inline {
		t.Fatalf("inline = %q, %v", got, err)
	}

	multi := "echo one\necho two\n"
	got, err = readPostBootScript(multi)
	if err != nil || string(got) != multi {
		t.Fatalf("multi-line inline = %q, %v", got, err)
	}
}

func TestReadPostBootScriptEmptyIsNil(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "empty.sh")
	if err := os.WriteFile(emptyFile, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "   ", "@" + emptyFile} {
		got, err := readPostBootScript(value)
		if err != nil {
			t.Fatalf("readPostBootScript(%q): %v", value, err)
		}
		if got != nil {
			t.Fatalf("readPostBootScript(%q) = %q, want nil", value, got)
		}
	}
}

func TestReadPostBootScriptMissingFileFails(t *testing.T) {
	_, err := readPostBootScript("@" + filepath.Join(t.TempDir(), "missing.sh"))
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("error = %v, want read error", err)
	}
}
