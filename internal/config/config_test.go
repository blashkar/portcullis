package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cfg, err := Parse([]byte(`
servers:
  git:
    command: [sandbox/run.sh, git]
  fs:
    command: [/opt/bin/run.sh, filesystem]
  docs:
    command: [docker, run, -i, --rm, img]
audit:
  max_payload: 1024
`), "/home/user/portcullis")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ServerNames(); !slices.Equal(got, []string{"docs", "fs", "git"}) {
		t.Errorf("ServerNames = %v", got)
	}
	tests := map[string]string{
		"git":  "/home/user/portcullis/sandbox/run.sh git", // relative to the config
		"fs":   "/opt/bin/run.sh filesystem",               // absolute
		"docs": "docker run -i --rm img",                   // looked up in PATH
	}
	for name, want := range tests {
		if got := strings.Join(cfg.CommandFor(name), " "); got != want {
			t.Errorf("CommandFor(%s) = %s, want %s", name, got, want)
		}
	}
	if cfg.Servers["git"].Command[0] != "sandbox/run.sh" {
		t.Error("CommandFor modified the config")
	}
	if got := cfg.AuditPath(); got != "/home/user/portcullis/portcullis.db" {
		t.Errorf("AuditPath = %s", got)
	}
	if cfg.MaxPayload() != 1024 {
		t.Errorf("MaxPayload = %d", cfg.MaxPayload())
	}
}

func TestAuditSettings(t *testing.T) {
	tests := []struct {
		yaml, path string
		payload    int
	}{
		{yaml: "audit: {path: /var/log/p.db}", path: "/var/log/p.db", payload: DefaultMaxPayload},
		{yaml: "audit: {path: logs/p.db}", path: "/cfg/logs/p.db", payload: DefaultMaxPayload},
		{yaml: "audit: {disabled: true}", path: ""},
	}
	for _, tt := range tests {
		cfg, err := Parse([]byte("servers: {fs: {command: [x]}}\n"+tt.yaml), "/cfg")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AuditPath() != tt.path {
			t.Errorf("%s: AuditPath = %q, want %q", tt.yaml, cfg.AuditPath(), tt.path)
		}
		if tt.payload != 0 && cfg.MaxPayload() != tt.payload {
			t.Errorf("%s: MaxPayload = %d", tt.yaml, cfg.MaxPayload())
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"no servers", "audit: {}", "no servers configured"},
		{"separator in name", "servers: {my__fs: {command: [x]}}", `server "my__fs": names use`},
		{"uppercase", "servers: {FS: {command: [x]}}", `server "FS": names use`},
		{"double hyphen", "servers: {a--b: {command: [x]}}", `server "a--b": names use`},
		{"empty command", "servers: {fs: {command: []}}", `server "fs": command is empty`},
		{"unknown key", "servers: {fs: {cmd: [x]}}", "field cmd not found"},
		{"negative payload", "servers: {fs: {command: [x]}}\naudit: {max_payload: -1}", "can't be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), "/cfg")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portcullis.yaml")
	if err := os.WriteFile(path, []byte("servers: {fs: {command: [./run.sh]}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.CommandFor("fs")[0]; got != filepath.Join(dir, "run.sh") {
		t.Errorf("command = %s", got)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}
