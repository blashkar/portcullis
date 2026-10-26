package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/policy"
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

func TestPolicySection(t *testing.T) {
	cfg, err := Parse([]byte(`
servers: {git: {command: [x]}}
policy:
  rules:
    - name: no-reset
      tool: git__git_reset
      action: deny
`), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := cfg.CompilePolicy()
	if err != nil || pol == nil {
		t.Fatalf("CompilePolicy = %v, %v", pol, err)
	}
	if d := pol.Check(policy.Call{Tool: "git__git_reset"}); d.Rule != "no-reset" {
		t.Errorf("decision = %+v", d)
	}

	cfg, err = Parse([]byte("servers: {git: {command: [x]}}"), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	if pol, err := cfg.CompilePolicy(); pol != nil || err != nil {
		t.Errorf("no policy section: %v, %v", pol, err)
	}

	for _, bad := range []string{
		"policy: {rules: [{tool: x, action: nope}]}",
		"policy: {rules: [{tool: x, action: deny, whne: 'true'}]}", // misspelled key
		"policy: {rules: [{tool: x, action: deny, when: 'args.'}]}",
	} {
		if _, err := Parse([]byte("servers: {git: {command: [x]}}\n"+bad), "/cfg"); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestGuardSettings(t *testing.T) {
	cfg, err := Parse([]byte("servers: {fs: {command: [x]}}"), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	// Secure by default.
	if cfg.PinsPath() != "/cfg/portcullis.pins.json" || cfg.HoldNewTools() || cfg.Scan.Tools != "" {
		t.Errorf("defaults: pins %q, hold %v, scan %q", cfg.PinsPath(), cfg.HoldNewTools(), cfg.Scan.Tools)
	}
	if r, err := cfg.Redactor(); r == nil || err != nil {
		t.Errorf("redactor = %v, %v", r, err)
	}

	cfg, err = Parse([]byte(`
servers: {fs: {command: [x]}}
pins: {path: /var/lib/pins.json, new_tools: hold}
scan: {tools: log, ignore: ["fs__*"]}
redact:
  patterns:
    - {name: internal_token, regex: 'itk_[a-z0-9]{8}'}
`), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PinsPath() != "/var/lib/pins.json" || !cfg.HoldNewTools() || !cfg.ScanIgnore().Match("fs__read_file") {
		t.Errorf("settings: %+v", cfg)
	}
	r, _ := cfg.Redactor()
	if out, _ := r.String("itk_abcd1234"); out != "[REDACTED:internal_token]" {
		t.Errorf("custom pattern: %q", out)
	}

	cfg, _ = Parse([]byte("servers: {fs: {command: [x]}}\npins: {disabled: true}\nredact: {disabled: true}"), "/cfg")
	if r, _ := cfg.Redactor(); cfg.PinsPath() != "" || r != nil {
		t.Error("disabling didn't")
	}

	for _, bad := range []string{
		"pins: {new_tools: trust}",
		"scan: {tools: block}",
		`scan: {ignore: [""]}`,
		"redact: {patterns: [{name: x, regex: '('}]}",
		"redact: {patterns: [{name: x, regex: 'a*'}]}",
		"redact: {patterns: [{regex: 'abc'}]}",
	} {
		if _, err := Parse([]byte("servers: {fs: {command: [x]}}\n"+bad), "/cfg"); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestInjectSettings(t *testing.T) {
	cfg, err := Parse([]byte(`
servers: {fs: {command: [x]}}
inject:
  action: block
  guard: {enabled: true, model: llama3.2:3b, check: suspicious, timeout: 5s}
`), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	if g := cfg.Inject.Guard; cfg.Inject.Action != "block" || !g.Enabled || g.Model != "llama3.2:3b" || g.Check != "suspicious" || g.Timeout != 5*time.Second {
		t.Errorf("inject = %+v", cfg.Inject)
	}
	for _, bad := range []string{
		"inject: {action: quarantine}",
		"inject: {guard: {check: some}}",
		"inject: {guard: {timeout: -1s}}",
		"inject: {guard: {timeout: soon}}",
	} {
		if _, err := Parse([]byte("servers: {fs: {command: [x]}}\n"+bad), "/cfg"); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestDashboardSettings(t *testing.T) {
	cfg, err := Parse([]byte("servers: {fs: {command: [x]}}\n"), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dashboard.Enabled || cfg.DashboardAddr() != DefaultDashboardAddr || cfg.DashboardURLPath() != filepath.Join("/cfg", DashboardURLFile) {
		t.Errorf("defaults: %+v, %s, %s", cfg.Dashboard, cfg.DashboardAddr(), cfg.DashboardURLPath())
	}
	for _, ok := range []string{"127.0.0.1:7878", "127.0.0.1:0", "localhost:9000", "[::1]:7878", "127.1.2.3:80"} {
		cfg, err := Parse([]byte("servers: {fs: {command: [x]}}\ndashboard: {enabled: true, addr: '"+ok+"', approval_timeout: 30s}\n"), "/cfg")
		if err != nil {
			t.Errorf("%s: %v", ok, err)
			continue
		}
		if cfg.DashboardAddr() != ok || cfg.Dashboard.ApprovalTimeout != 30*time.Second {
			t.Errorf("%s: %+v", ok, cfg.Dashboard)
		}
	}
	// Anything reachable from another machine is refused, as are typos.
	for _, bad := range []string{"0.0.0.0:7878", ":7878", "192.0.2.10:7878", "[::]:7878", "example.com:7878", "127.0.0.1", "127.0.0.1:http", "127.0.0.1:70000"} {
		if _, err := Parse([]byte("servers: {fs: {command: [x]}}\ndashboard: {addr: '"+bad+"'}\n"), "/cfg"); err == nil {
			t.Errorf("addr %s: no error", bad)
		}
	}
	if _, err := Parse([]byte("servers: {fs: {command: [x]}}\ndashboard: {approval_timeout: -1s}\n"), "/cfg"); err == nil {
		t.Error("negative timeout: no error")
	}
}

func TestMetricsSettings(t *testing.T) {
	cfg, err := Parse([]byte("servers: {fs: {command: [x]}}\n"), "/cfg")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.Enabled || cfg.MetricsAddr() != DefaultMetricsAddr {
		t.Errorf("defaults: %+v, %s", cfg.Metrics, cfg.MetricsAddr())
	}
	cfg, err = Parse([]byte("servers: {fs: {command: [x]}}\nmetrics: {enabled: true, addr: 'localhost:9100'}\n"), "/cfg")
	if err != nil || !cfg.Metrics.Enabled || cfg.MetricsAddr() != "localhost:9100" {
		t.Errorf("%+v, %v", cfg, err)
	}
	for _, bad := range []string{"0.0.0.0:9464", ":9464", "192.0.2.10:9464"} {
		_, err := Parse([]byte("servers: {fs: {command: [x]}}\nmetrics: {addr: '"+bad+"'}\n"), "/cfg")
		if err == nil || !strings.Contains(err.Error(), "metrics.addr") {
			t.Errorf("addr %s: %v", bad, err)
		}
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// A file with only a policy, and no servers, is fine.
	p, err := LoadPolicy(write("new.yaml", "policy:\n  rules:\n    - tool: git__*\n      action: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Check(policy.Call{Tool: "git__git_reset"}); d.Outcome() != "deny" {
		t.Errorf("git__git_reset: %+v", d)
	}
	for name, body := range map[string]string{
		"none.yaml":  "servers: {fs: {command: [x]}}\n",
		"typo.yaml":  "polcy: {default: deny}\n",
		"bad.yaml":   "policy: {default: maybe}\n",
		"empty.yaml": "",
	} {
		if _, err := LoadPolicy(write(name, body)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
