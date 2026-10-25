package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/ollama"
)

// When this env var is set, the test binary runs as an MCP server instead
// of running tests.
const fakeServerEnv = "PORTCULLIS_AGENT_FAKE_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(fakeServerEnv) != "" {
		os.Exit(fakeServer())
	}
	os.Exit(m.Run())
}

// fakeServer is an MCP server on stdio with one tool, read_file.
func fakeServer() int {
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-files", Version: "1"}, nil)
	type args struct {
		Path string `json:"path"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "read_file", Description: "Read a file"},
		func(_ context.Context, _ *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "contents of " + in.Path}}}, nil, nil
		})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// fakeOllama asks for read_file when the last message is the user's, and
// answers with the tool's output once the result comes back.
func fakeOllama(t *testing.T, capabilities string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			fmt.Fprintf(w, `{"capabilities":%s}`, capabilities)
		case "/api/chat":
			var req ollama.ChatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			last := req.Messages[len(req.Messages)-1]
			if last.Role == "user" {
				path := strings.TrimPrefix(last.Content, "read ")
				fmt.Fprintf(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"read_file","arguments":{"path":%q}}}]},"done":false}`+"\n", path)
				fmt.Fprintln(w, `{"message":{"role":"assistant","content":""},"done":true}`)
				return
			}
			fmt.Fprintf(w, `{"message":{"role":"assistant","content":"It says: "},"done":false}`+"\n")
			fmt.Fprintf(w, `{"message":{"role":"assistant","content":%q},"done":true}`+"\n", last.Content)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// build compiles the package at pkg into a binary called name.
func build(t *testing.T, name, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

// runAgentBinary runs portcullis-agent with stdin and returns stdout and stderr.
func runAgentBinary(t *testing.T, agentBin, ollamaURL, stdin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(agentBin, args...)
	cmd.Env = append(os.Environ(), "OLLAMA_HOST="+ollamaURL, fakeServerEnv+"=1")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// The whole chain: portcullis-agent -> portcullis wrap -> MCP server, with a
// fake Ollama in place of a real model.
func TestAgentThroughProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binaries")
	}
	agentBin := build(t, "portcullis-agent", ".")
	proxyBin := build(t, "portcullis", "../portcullis")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ollamaSrv := fakeOllama(t, `["completion","tools"]`)
	logFile := filepath.Join(t.TempDir(), "proxy.log")
	server := []string{"--", proxyBin, "wrap", "--log-file", logFile, "--", self, "-test.run=^$"}

	t.Run("one-shot prompt", func(t *testing.T) {
		stdout, stderr, err := runAgentBinary(t, agentBin, ollamaSrv.URL, "", append([]string{"-p", "read /w/a.txt"}, server...)...)
		if err != nil {
			t.Fatalf("%v\nstderr:\n%s", err, stderr)
		}
		// Only the answer goes to stdout, so it can be piped.
		if stdout != "It says: contents of /w/a.txt\n" {
			t.Errorf("stdout = %q", stdout)
		}
		if !strings.Contains(stderr, `-> read_file {"path":"/w/a.txt"}`) || !strings.Contains(stderr, "<- read_file: 20 bytes: contents of /w/a.txt") {
			t.Errorf("stderr doesn't show the tool call:\n%s", stderr)
		}
	})

	t.Run("repl", func(t *testing.T) {
		stdin := "/tools\nread /w/one\n\n/reset\nread /w/two\n/quit\nread /never\n"
		stdout, stderr, err := runAgentBinary(t, agentBin, ollamaSrv.URL, stdin, server...)
		if err != nil {
			t.Fatalf("%v\nstderr:\n%s", err, stderr)
		}
		if stdout != "It says: contents of /w/one\nIt says: contents of /w/two\n" {
			t.Errorf("stdout = %q", stdout)
		}
		for _, want := range []string{"with 1 tools from fake-files", "  read_file: Read a file", "Conversation cleared."} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr is missing %q:\n%s", want, stderr)
			}
		}
		if strings.Contains(stderr, "/never") {
			t.Error("kept reading after /quit")
		}
	})

	// The proxy saw the agent's calls.
	logs, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(logs), `"tool":"read_file"`); n != 6 { // 3 calls, each request + response
		t.Errorf("proxy logged %d read_file messages, want 6:\n%s", n, logs)
	}
}

func TestAgentChecksModel(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	agentBin := build(t, "portcullis-agent", ".")

	noTools := fakeOllama(t, `["completion"]`)
	_, stderr, err := runAgentBinary(t, agentBin, noTools.URL, "", "-m", "plain", "--", "true")
	if err == nil || !strings.Contains(stderr, "model plain doesn't support tool calling") {
		t.Errorf("err = %v, stderr = %q", err, stderr)
	}

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"model 'gone' not found"}`)
	}))
	defer missing.Close()
	_, stderr, err = runAgentBinary(t, agentBin, missing.URL, "", "-m", "gone", "--", "true")
	if err == nil || !strings.Contains(stderr, "run `ollama pull gone`") {
		t.Errorf("err = %v, stderr = %q", err, stderr)
	}
}

func TestAgentReportsServerStartupFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	agentBin := build(t, "portcullis-agent", ".")
	ollamaSrv := fakeOllama(t, `["tools"]`)
	_, stderr, err := runAgentBinary(t, agentBin, ollamaSrv.URL, "", "--", "sh", "-c", "echo 'cannot open database' >&2; exit 1")
	if err == nil || !strings.Contains(stderr, "starting the MCP server") || !strings.Contains(stderr, "cannot open database") {
		t.Errorf("err = %v, stderr = %q", err, stderr)
	}
}

func TestPreview(t *testing.T) {
	if got := preview("a\n  b\tc", 10); got != "a b c" {
		t.Errorf("preview collapses whitespace: %q", got)
	}
	if got := preview("héllo wörld", 5); got != "héllo…" {
		t.Errorf("preview truncates by rune: %q", got)
	}
}

func TestTailBuffer(t *testing.T) {
	tb := &tailBuffer{max: 5}
	fmt.Fprint(tb, "abc")
	fmt.Fprint(tb, "defg")
	if tb.String() != "cdefg" {
		t.Errorf("tail = %q", tb.String())
	}
}
