package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var pendingID = regexp.MustCompile(`name="id" value="([^"]+)"`)

// decideInDashboard waits for a call to show up on the dashboard and
// approves or denies it, as a person clicking the button would.
func decideInDashboard(t *testing.T, dashURL, tool, decision string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(dashURL + "main")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if m := pendingID.FindSubmatch(body); m != nil && strings.Contains(string(body), tool) {
			res, err := http.PostForm(dashURL+"approvals", url.Values{"id": {string(m[1])}, "decision": {decision}})
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK { // the redirect to the page was followed
				t.Fatalf("posting %s = %d", decision, res.StatusCode)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never showed up on the dashboard", tool)
}

func TestServeAsksForApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, dbPath := writeConfig(t, "alpha", "beta")
	appendConfig(t, cfgPath, `dashboard:
  enabled: true
  addr: 127.0.0.1:0
policy:
  rules:
    - name: ask-first
      tool: "*__whoami"
      action: require_approval
`)
	ctx := context.Background()
	cmd := exec.Command(bin, "serve", "--config", cfgPath)
	cmd.Env = append(os.Environ(), fakeMCPEnv+"=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0.1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nstderr:\n%s", err, stderr.String())
	}

	out, err := exec.Command(bin, "dashboard", "--config", cfgPath).Output()
	if err != nil {
		t.Fatalf("portcullis dashboard: %v", err)
	}
	dashURL := strings.TrimSpace(string(out))
	if !strings.HasPrefix(dashURL, "http://127.0.0.1:") || !strings.HasSuffix(dashURL, "/") {
		t.Fatalf("dashboard URL %q", dashURL)
	}
	urlFile := filepath.Join(filepath.Dir(cfgPath), "portcullis.dashboard")
	if fi, err := os.Stat(urlFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("URL file: %v, %v", fi.Mode(), err)
	}

	done := make(chan string, 1)
	go func() {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "alpha__whoami"})
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- res.Content[0].(*mcp.TextContent).Text
	}()
	decideInDashboard(t, dashURL, "alpha__whoami", "approve")
	if got := <-done; got != "I am alpha" {
		t.Errorf("approved call = %q", got)
	}

	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "beta__whoami"})
		done <- "error: " + errString(err)
	}()
	decideInDashboard(t, dashURL, "beta__whoami", "deny")
	if got := <-done; !strings.Contains(got, `a person denied beta__whoami (rule "ask-first")`) {
		t.Errorf("denied call = %q", got)
	}

	// The timeline shows both calls and how they ended.
	res, err := http.Get(dashURL + "main?show=caught")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	for _, want := range []string{`<span class="who">you</span> denied`, "beta__whoami"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("timeline lacks %q", want)
		}
	}
	if strings.Contains(string(page), "alpha__whoami") {
		t.Error("an approved call is listed as caught")
	}

	// The other pages read the running gateway and the audit log.
	get := func(path string) string {
		t.Helper()
		res, err := http.Get(dashURL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	servers := get("servers-main")
	for _, want := range []string{`<span class="tool big">alpha</span>`, `<span class="tool big">beta</span>`, "alpha__whoami", "needs approval", "not sandboxed"} {
		if !strings.Contains(servers, want) {
			t.Errorf("servers page lacks %q", want)
		}
	}
	sessions := get("sessions-main")
	if !strings.Contains(sessions, "this one") || !strings.Contains(sessions, "e2e-client") {
		t.Errorf("sessions page:\n%s", sessions)
	}
	if security := get("security-main"); !strings.Contains(security, "Denied by you") {
		t.Error("security page lacks the denial")
	}

	_ = cs.Close()
	_ = cmd.Wait()
	token := strings.TrimSuffix(dashURL[strings.LastIndex(strings.TrimSuffix(dashURL, "/"), "/")+1:], "/")
	if strings.Contains(stderr.String(), token) {
		t.Error("the dashboard's token is in the logs")
	}
	if _, err := os.Stat(urlFile); !os.IsNotExist(err) {
		t.Errorf("the URL file is still there after serve exited: %v", err)
	}

	out, err = exec.Command(bin, "audit", "--db", dbPath, "--method", "tools/call").Output()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !strings.Contains(string(out), "require_approval ask-first") || !strings.Contains(string(out), "reason: denied in the dashboard") {
		t.Errorf("audit:\n%s", out)
	}
	// An approved call went ahead, so it isn't "blocked".
	if !regexp.MustCompile(`approved ask-first +ok\n +reason: approved in the dashboard`).Match(out) {
		t.Errorf("approved call in the audit log:\n%s", out)
	}
}

func TestServeWithoutDashboardBlocksApprovals(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)
	cfgPath, _ := writeConfig(t, "alpha")
	appendConfig(t, cfgPath, "policy:\n  rules:\n    - tool: alpha__whoami\n      action: require_approval\n")
	_, results := serveOnce(t, bin, cfgPath, nil, "alpha__whoami")
	if len(results) != 1 || !strings.Contains(results[0], "no approver is configured") {
		t.Errorf("results = %q", results)
	}
	if out, err := exec.Command(bin, "dashboard", "--config", cfgPath).CombinedOutput(); err == nil || !strings.Contains(string(out), "doesn't turn the dashboard on") {
		t.Errorf("portcullis dashboard: %v\n%s", err, out)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
