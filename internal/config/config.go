// Package config loads the portcullis serve configuration: which upstream
// MCP servers to run, where to keep the audit log, the policy that decides
// which tool calls may go ahead, and the checks on what servers send back.
//
//	servers:
//	  fs:
//	    command: [sandbox/run.sh, filesystem]
//	  git:
//	    command: [sandbox/run.sh, git]
//	audit:
//	  path: portcullis.db
//	policy:
//	  rules:
//	    - tool: git__git_reset
//	      action: deny
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/blashkar/portcullis/internal/glob"
	"github.com/blashkar/portcullis/internal/policy"
	"github.com/blashkar/portcullis/internal/redact"
)

// Separator joins a server's name and one of its tool or prompt names:
// fs__read_file. Server names can't contain it, so the first occurrence
// always marks the end of the server name.
const Separator = "__"

// DefaultAuditPath is the audit database, relative to the config file.
const DefaultAuditPath = "portcullis.db"

// DefaultPinsPath is the pin file, relative to the config file.
const DefaultPinsPath = "portcullis.pins.json"

// DefaultMaxPayload caps how much of each message's params and result is
// stored in the audit log.
const DefaultMaxPayload = 64 << 10

// Config is a parsed configuration file.
type Config struct {
	Servers map[string]Server `yaml:"servers"`
	Audit   Audit             `yaml:"audit"`
	// Policy decides which tool calls may go ahead; see package policy.
	Policy policy.Spec `yaml:"policy"`
	Pins   Pins        `yaml:"pins"`
	Scan   Scan        `yaml:"scan"`
	Redact Redact      `yaml:"redact"`
	Inject Inject      `yaml:"inject"`
	// Dashboard is the local web page where calls are approved.
	Dashboard Dashboard `yaml:"dashboard"`

	// Dir is the directory of the config file. Relative paths in the config
	// are resolved against it, so a client can start portcullis from anywhere.
	Dir string `yaml:"-"`
}

// Server is one upstream MCP server, started as a child process.
type Server struct {
	// Command is the program and its arguments. A program path containing a
	// slash is relative to the config file; a bare name is looked up in PATH.
	Command []string `yaml:"command"`
}

// Audit configures the audit log.
type Audit struct {
	// Path is the SQLite database; "" means DefaultAuditPath.
	Path string `yaml:"path"`
	// Disabled turns the audit log off.
	Disabled bool `yaml:"disabled"`
	// MaxPayload caps the stored params and result of each message, in
	// bytes; 0 means DefaultMaxPayload.
	MaxPayload int `yaml:"max_payload"`
}

// Pins configures tool pinning: holding back a tool whose definition
// changed since it was approved.
type Pins struct {
	// Path is the pin file; "" means DefaultPinsPath.
	Path     string `yaml:"path"`
	Disabled bool   `yaml:"disabled"`
	// NewTools is what happens to a tool seen for the first time: "pin"
	// (the default) trusts it and pins it; "hold" holds it until approved.
	NewTools string `yaml:"new_tools"`
}

// Scan configures the tool-poisoning scanner.
type Scan struct {
	// Tools is what happens to a tool whose definition has a high-severity
	// finding: "hide" (the default), "log", or "off" to skip scanning.
	Tools string `yaml:"tools"`
	// Ignore lists tool patterns not to scan, for tools you have reviewed.
	Ignore []string `yaml:"ignore"`
}

// Redact configures secret redaction in what servers send back.
type Redact struct {
	Disabled bool `yaml:"disabled"`
	// Patterns are extra secrets to redact, after the built-in ones.
	Patterns []RedactPattern `yaml:"patterns"`
}

// Inject configures prompt-injection checks on tool results and resources.
type Inject struct {
	// Action is what happens to a result that looks like an injection:
	// "warn" (the default) puts a warning before it, "block" withholds it,
	// "log" only records it, and "off" skips the checks.
	Action string `yaml:"action"`
	Guard  Guard  `yaml:"guard"`
}

// Guard configures the guard model: a local model, through Ollama, that
// judges text the patterns don't catch.
type Guard struct {
	Enabled bool `yaml:"enabled"`
	// Model defaults to inject.DefaultModel.
	Model string `yaml:"model"`
	// Host is Ollama's URL; "" means OLLAMA_HOST, or localhost.
	Host string `yaml:"host"`
	// Check is "all" (the default) to ask about every result, or
	// "suspicious" to ask only about results a pattern noticed.
	Check   string        `yaml:"check"`
	Timeout time.Duration `yaml:"timeout"`
}

// Dashboard configures the local web dashboard: calls waiting for a
// person's approval, tools held back, and live activity.
type Dashboard struct {
	// Enabled turns it on. Without it, calls a rule says need approval are
	// blocked.
	Enabled bool `yaml:"enabled"`
	// Addr is where it listens; "" means DefaultDashboardAddr. Only loopback
	// addresses are allowed: it can approve tool calls.
	Addr string `yaml:"addr"`
	// ApprovalTimeout is how long a call waits for a decision before it is
	// denied; 0 means two minutes.
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
}

// DefaultDashboardAddr is where the dashboard listens by default.
const DefaultDashboardAddr = "127.0.0.1:7878"

// DashboardURLFile holds the running dashboard's URL, token included,
// relative to the config file. "portcullis dashboard" reads it.
const DashboardURLFile = "portcullis.dashboard"

// RedactPattern is a custom secret format. A group named "secret" limits
// the redaction to that part of the match.
type RedactPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

var serverName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data, dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a config. dir is the directory relative paths
// are resolved against.
func Parse(data []byte, dir string) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelled key is an error, not silently ignored
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	cfg.Dir = dir
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return errors.New("no servers configured")
	}
	var errs []error
	for _, name := range c.ServerNames() {
		s := c.Servers[name]
		switch {
		case !serverName.MatchString(name) || strings.Contains(name, "--"):
			errs = append(errs, fmt.Errorf("server %q: names use lowercase letters, digits and single hyphens", name))
		case len(s.Command) == 0 || s.Command[0] == "":
			errs = append(errs, fmt.Errorf("server %q: command is empty", name))
		}
	}
	if c.Audit.MaxPayload < 0 {
		errs = append(errs, errors.New("audit.max_payload can't be negative"))
	}
	if _, err := c.CompilePolicy(); err != nil {
		errs = append(errs, err)
	}
	switch c.Pins.NewTools {
	case "", "pin", "hold":
	default:
		errs = append(errs, fmt.Errorf("pins.new_tools must be pin or hold, not %q", c.Pins.NewTools))
	}
	switch c.Scan.Tools {
	case "", "hide", "log", "off":
	default:
		errs = append(errs, fmt.Errorf("scan.tools must be hide, log or off, not %q", c.Scan.Tools))
	}
	if _, err := glob.Compile(c.Scan.Ignore); err != nil {
		errs = append(errs, fmt.Errorf("scan.ignore: %w", err))
	}
	if _, err := c.Redactor(); err != nil {
		errs = append(errs, err)
	}
	switch c.Inject.Action {
	case "", "warn", "block", "log", "off":
	default:
		errs = append(errs, fmt.Errorf("inject.action must be warn, block, log or off, not %q", c.Inject.Action))
	}
	switch c.Inject.Guard.Check {
	case "", "all", "suspicious":
	default:
		errs = append(errs, fmt.Errorf("inject.guard.check must be all or suspicious, not %q", c.Inject.Guard.Check))
	}
	if c.Inject.Guard.Timeout < 0 {
		errs = append(errs, errors.New("inject.guard.timeout can't be negative"))
	}
	if err := checkLoopback(c.DashboardAddr()); err != nil {
		errs = append(errs, fmt.Errorf("dashboard.addr: %w", err))
	}
	if c.Dashboard.ApprovalTimeout < 0 {
		errs = append(errs, errors.New("dashboard.approval_timeout can't be negative"))
	}
	return errors.Join(errs...)
}

// checkLoopback checks that addr is a host and port on this machine only.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("bad port %q", port)
	}
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s isn't a loopback address such as 127.0.0.1; the dashboard can approve tool calls, so it must not be reachable from other machines", host)
}

// DashboardAddr returns where the dashboard listens.
func (c *Config) DashboardAddr() string {
	if c.Dashboard.Addr == "" {
		return DefaultDashboardAddr
	}
	return c.Dashboard.Addr
}

// DashboardURLPath returns the file that holds the running dashboard's URL.
func (c *Config) DashboardURLPath() string {
	return c.resolve("", DashboardURLFile)
}

// PinsPath returns the pin file's path, or "" if pinning is off.
func (c *Config) PinsPath() string {
	if c.Pins.Disabled {
		return ""
	}
	return c.resolve(c.Pins.Path, DefaultPinsPath)
}

// HoldNewTools reports whether tools seen for the first time wait for
// approval.
func (c *Config) HoldNewTools() bool {
	return c.Pins.NewTools == "hold"
}

// ScanIgnore returns the compiled scan.ignore patterns.
func (c *Config) ScanIgnore() glob.Patterns {
	p, _ := glob.Compile(c.Scan.Ignore) // checked by validate
	return p
}

// Redactor returns the redactor, or nil if redaction is off.
func (c *Config) Redactor() (*redact.Redactor, error) {
	if c.Redact.Disabled {
		return nil, nil
	}
	var extra []redact.Rule
	for i, p := range c.Redact.Patterns {
		if p.Name == "" {
			return nil, fmt.Errorf("redact.patterns[%d]: no name", i)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("redact.patterns[%d] (%s): %w", i, p.Name, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("redact.patterns[%d] (%s): the pattern matches empty text", i, p.Name)
		}
		extra = append(extra, redact.Rule{Name: p.Name, Pattern: re})
	}
	return redact.New(extra...), nil
}

// CompilePolicy compiles the policy section. It returns nil, which allows
// every call, if the config has no policy.
func (c *Config) CompilePolicy() (*policy.Policy, error) {
	if c.Policy.Default == "" && !c.Policy.LogOnly && len(c.Policy.Rules) == 0 {
		return nil, nil
	}
	return policy.Compile(c.Policy)
}

// ServerNames returns the server names in sorted order.
func (c *Config) ServerNames() []string {
	names := make([]string, 0, len(c.Servers))
	for name := range c.Servers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// CommandFor returns the server's command with its program path resolved.
func (c *Config) CommandFor(name string) []string {
	cmd := slices.Clone(c.Servers[name].Command)
	if strings.Contains(cmd[0], "/") && !filepath.IsAbs(cmd[0]) {
		cmd[0] = filepath.Join(c.Dir, cmd[0])
	}
	return cmd
}

// AuditPath returns the audit database's path, or "" if auditing is off.
func (c *Config) AuditPath() string {
	if c.Audit.Disabled {
		return ""
	}
	return c.resolve(c.Audit.Path, DefaultAuditPath)
}

// resolve returns p, or def if p is empty, relative to the config's directory.
func (c *Config) resolve(p, def string) string {
	if p == "" {
		p = def
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.Dir, p)
	}
	return p
}

// MaxPayload returns the audit payload cap in bytes.
func (c *Config) MaxPayload() int {
	if c.Audit.MaxPayload == 0 {
		return DefaultMaxPayload
	}
	return c.Audit.MaxPayload
}
