package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeMCPServer is an SDK server with one tool, whoami, that answers with
// the server's name.
func fakeMCPServer(name string) int {
	server := mcp.NewServer(&mcp.Implementation{Name: name, Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "I am " + name}}}, nil, nil
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// writeConfig writes a config whose servers are this test binary.
func writeConfig(t *testing.T, servers ...string) (cfgPath, dbPath string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("servers:\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "  %s:\n    command: [%q, %q]\n", s, self, s)
	}
	b.WriteString("audit:\n  path: audit.db\n")
	cfgPath = filepath.Join(dir, "portcullis.yaml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(dir, "audit.db")
}

func TestServeAndAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, dbPath := writeConfig(t, "alpha", "beta")
	ctx := context.Background()

	cmd := exec.Command(bin, "serve", "--config", cfgPath)
	cmd.Env = append(os.Environ(), fakeMCPEnv+"=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0.1"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nstderr:\n%s", err, stderr.String())
	}

	var tools []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		tools = append(tools, tool.Name)
	}
	slices.Sort(tools)
	if !slices.Equal(tools, []string{"alpha__whoami", "beta__whoami"}) {
		t.Fatalf("tools = %v", tools)
	}
	for _, name := range []string{"alpha", "beta"} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name + "__whoami"})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Content[0].(*mcp.TextContent).Text; got != "I am "+name {
			t.Errorf("%s__whoami = %q", name, got)
		}
	}
	if err := cs.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	if err := cmd.Wait(); err != nil && !strings.Contains(err.Error(), "Wait was already called") {
		t.Logf("wait: %v", err)
	}
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("portcullis serve didn't exit cleanly; stderr:\n%s", stderr.String())
	}

	// The audit log has the calls, and the CLI can read them back.
	out, err := exec.Command(bin, "audit", "--db", dbPath, "--json", "--method", "tools/call").Output()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	var calls []map[string]any
	for line := range strings.Lines(string(out)) {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad JSON line %q: %v", line, err)
		}
		calls = append(calls, e)
	}
	if len(calls) != 2 || calls[0]["tool"] != "alpha__whoami" || calls[0]["server"] != "alpha" || calls[1]["tool"] != "beta__whoami" {
		t.Errorf("audited calls = %v", calls)
	}
	if res, _ := calls[0]["result"].(map[string]any); res == nil || !strings.Contains(fmt.Sprint(res["content"]), "I am alpha") {
		t.Errorf("result not recorded: %v", calls[0]["result"])
	}

	out, err = exec.Command(bin, "audit", "sessions", "--db", dbPath).Output()
	if err != nil {
		t.Fatalf("audit sessions: %v", err)
	}
	if !strings.Contains(string(out), "e2e-client 0.1") || !strings.Contains(string(out), "alpha,beta") {
		t.Errorf("sessions:\n%s", out)
	}

	// Through the config file instead of --db, and filtering by tool prefix.
	out, err = exec.Command(bin, "audit", "--config", cfgPath, "--tool", "beta__*").Output()
	if err != nil {
		t.Fatalf("audit --config: %v", err)
	}
	if !strings.Contains(string(out), "beta__whoami") || strings.Contains(string(out), "alpha__whoami") {
		t.Errorf("filtered audit:\n%s", out)
	}
}

func TestServeFailsIfAServerCantStart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, _ := writeConfig(t, "alpha")
	// Add a server that doesn't exist.
	data, _ := os.ReadFile(cfgPath)
	data = []byte(strings.Replace(string(data), "servers:\n", "servers:\n  broken:\n    command: [/nonexistent/server]\n", 1))
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "serve", "--config", cfgPath)
	cmd.Env = append(os.Environ(), fakeMCPEnv+"=1")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != exitError || !strings.Contains(string(out), "starting server broken") {
		t.Errorf("exit %d, output:\n%s", cmd.ProcessState.ExitCode(), out)
	}
}

func TestAuditWithoutALog(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	missing := filepath.Join(t.TempDir(), "none.db")
	out, err := exec.Command(bin, "audit", "--db", missing).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no audit log at") {
		t.Errorf("err %v, output %s", err, out)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("audit created a database")
	}
}

func TestPrefixWriter(t *testing.T) {
	var b strings.Builder
	w := &prefixWriter{w: &b, prefix: "[fs] "}
	fmt.Fprint(w, "one\ntw")
	fmt.Fprint(w, "o\nthree")
	if got := b.String(); got != "[fs] one\n[fs] two\n" {
		t.Errorf("got %q", got)
	}
}
