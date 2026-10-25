// Package config loads the portcullis serve configuration: which upstream
// MCP servers to run and where to keep the audit log.
//
//	servers:
//	  fs:
//	    command: [sandbox/run.sh, filesystem]
//	  git:
//	    command: [sandbox/run.sh, git]
//	audit:
//	  path: portcullis.db
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Separator joins a server's name and one of its tool or prompt names:
// fs__read_file. Server names can't contain it, so the first occurrence
// always marks the end of the server name.
const Separator = "__"

// DefaultAuditPath is the audit database, relative to the config file.
const DefaultAuditPath = "portcullis.db"

// DefaultMaxPayload caps how much of each message's params and result is
// stored in the audit log.
const DefaultMaxPayload = 64 << 10

// Config is a parsed configuration file.
type Config struct {
	Servers map[string]Server `yaml:"servers"`
	Audit   Audit             `yaml:"audit"`

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
	return errors.Join(errs...)
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
	p := c.Audit.Path
	if p == "" {
		p = DefaultAuditPath
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
