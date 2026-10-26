package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, dbPath := writeConfig(t, "alpha", "beta")
	appendConfig(t, cfgPath, `policy:
  rules:
    - name: no-beta
      tool: beta__*
      action: deny
`)
	_, results := serveOnce(t, bin, cfgPath, nil, "alpha__whoami", "beta__whoami", "alpha__whoami")
	if results[0] != "I am alpha" || !strings.Contains(results[1], "no-beta") {
		t.Fatalf("results = %q", results)
	}

	newPolicy := filepath.Join(t.TempDir(), "new.yaml")
	if err := os.WriteFile(newPolicy, []byte(`policy:
  rules:
    - name: alpha-budget
      tool: alpha__*
      rate_limit: 1/hour
`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "replay", "--db", dbPath, "--policy", newPolicy).CombinedOutput()
	if err != nil {
		t.Fatalf("replay: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		`beta__whoami +deny no-beta +allow +now allowed\n`,
		`alpha__whoami +allow +rate_limit alpha-budget +now blocked\n +reason: rate limit of 1/hour exceeded\n`,
		`\n3 tool calls replayed: 2 decided differently \(1 now blocked, 1 now allowed\)\n`,
	} {
		if !regexp.MustCompile(want).MatchString(got) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// The first alpha call is within the limit, so it is shown only with --all.
	if strings.Count(got, "alpha__whoami") != 1 {
		t.Errorf("unchanged calls shown:\n%s", got)
	}
	// Arguments can hold secrets, so they're shown only when asked for.
	if strings.Contains(got, "args:") {
		t.Errorf("arguments shown without --payloads:\n%s", got)
	}
	if out, err := exec.Command(bin, "replay", "--db", dbPath, "--policy", newPolicy, "--payloads").Output(); err != nil || strings.Count(string(out), "args: {}") != 2 {
		t.Errorf("--payloads: %v\n%s", err, out)
	}
	out, err = exec.Command(bin, "replay", "all", "--db", dbPath, "--policy", newPolicy, "--all", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var changed []bool
	for line := range strings.Lines(string(out)) {
		var r struct {
			Tool    string `json:"tool"`
			Changed bool   `json:"changed"`
			After   struct {
				Decision string `json:"decision"`
			} `json:"after"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		changed = append(changed, r.Changed)
	}
	if len(changed) != 3 || changed[0] || !changed[1] || !changed[2] {
		t.Errorf("--json --all:\n%s", out)
	}

	// The current policy decides every call as it was decided.
	out, err = exec.Command(bin, "replay", "--db", dbPath, "--policy", cfgPath).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "3 tool calls replayed: 0 decided differently") {
		t.Errorf("same policy: %v\n%s", err, out)
	}

	// A broken policy is reported before anything else.
	if err := os.WriteFile(newPolicy, []byte("policy: {default: maybe}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "replay", "--db", dbPath, "--policy", newPolicy).CombinedOutput(); err == nil || !strings.Contains(string(out), "default must be allow or deny") {
		t.Errorf("bad policy: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "replay", "--db", dbPath).CombinedOutput(); err == nil || !strings.Contains(string(out), `"policy" not set`) {
		t.Errorf("no --policy: %v\n%s", err, out)
	}
}

func TestServeMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, _ := writeConfig(t, "alpha")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	appendConfig(t, cfgPath, "metrics:\n  enabled: true\n  addr: "+addr+"\n")

	ctx := context.Background()
	cmd := exec.Command(bin, "serve", "--config", cfgPath)
	cmd.Env = append(os.Environ(), fakeMCPEnv+"=1")
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0.1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cs.Close()
		_ = cmd.Wait()
	}()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "alpha__whoami"}); err != nil {
		t.Fatal(err)
	}
	res, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	for _, want := range []string{
		`portcullis_tool_calls_total{decision="none",outcome="ok",server="alpha",tool="alpha__whoami"} 1`,
		`portcullis_tool_definitions_total{result="pinned",server="alpha"} 1`,
		`portcullis_tools_offered 1`,
		`portcullis_tools_held 0`,
	} {
		if !strings.Contains(string(body), "\n"+want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("metrics:\n%s", body)
	}
}
