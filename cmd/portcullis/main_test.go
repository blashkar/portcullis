package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/jsonrpc"
)

// When this env var is set, the test binary acts as the upstream MCP server
// instead of running tests. Its value picks the server's behavior.
const fakeServerEnv = "PORTCULLIS_FAKE_SERVER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeServerEnv); mode != "" {
		os.Exit(fakeServer(mode))
	}
	os.Exit(m.Run())
}

// fakeServer answers each request with {"echo": method}. Modes:
//
//	echo      exit 0 when stdin closes
//	exit3     exit 3 after the first request
//	stubborn  keep running after stdin closes, until signaled
func fakeServer(mode string) int {
	fmt.Fprintln(os.Stderr, "fake server: started") // MCP servers log on stderr
	r := jsonrpc.NewReader(os.Stdin, 0)
	w := jsonrpc.NewWriter(os.Stdout)
	for {
		raw, err := r.Read()
		if err != nil {
			break
		}
		msg, err := jsonrpc.Parse(raw)
		if err != nil || msg.Kind() != jsonrpc.KindRequest {
			continue
		}
		_ = w.Write(fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"result":{"echo":%q}}`, msg.ID, msg.Method))
		if mode == "exit3" {
			return 3
		}
	}
	if mode == "stubborn" {
		time.Sleep(time.Hour) // until SIGTERM; a bare select{} would trip the deadlock detector
	}
	return 0
}

// buildPortcullis compiles the command once per test run.
func buildPortcullis(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "portcullis")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

type session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	stderr *bytes.Buffer
}

// startWrapped runs "portcullis wrap -- <this test binary>" with the fake
// server in the given mode.
func startWrapped(t *testing.T, bin, mode string, flags ...string) *session {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"wrap"}, flags...)
	args = append(args, "--", self, "-test.run=^$") // flags after "--" belong to the server
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), fakeServerEnv+"="+mode)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return &session{cmd: cmd, stdin: stdin, stdout: bufio.NewScanner(stdout), stderr: &stderr}
}

func (s *session) call(t *testing.T, id int, method string) {
	t.Helper()
	fmt.Fprintf(s.stdin, `{"jsonrpc":"2.0","id":%d,"method":%q}`+"\n", id, method)
	if !s.stdout.Scan() {
		t.Fatalf("no response to %s; stderr:\n%s", method, s.stderr)
	}
	want := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"echo":%q}}`, id, method)
	if got := s.stdout.Text(); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// wait waits for portcullis to exit and returns its exit code.
func (s *session) wait(t *testing.T, timeout time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(timeout):
		t.Fatalf("portcullis didn't exit within %v; stderr:\n%s", timeout, s.stderr)
		return -1
	}
}

func TestWrap(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildPortcullis(t)

	t.Run("relays and exits when the client hangs up", func(t *testing.T) {
		s := startWrapped(t, bin, "echo")
		s.call(t, 1, "initialize")
		s.call(t, 2, "tools/list")
		s.stdin.Close()
		if code := s.wait(t, 5*time.Second); code != 0 {
			t.Fatalf("exit code %d; stderr:\n%s", code, s.stderr)
		}
		if s.stdout.Scan() {
			t.Errorf("unexpected output on stdout: %s", s.stdout.Text())
		}
		logs := s.stderr.String()
		for _, want := range []string{"fake server: started", "session started", "method=tools/list", `reason="client closed"`} {
			if !strings.Contains(logs, want) {
				t.Errorf("stderr is missing %q:\n%s", want, logs)
			}
		}
	})

	t.Run("exits with the server's exit code", func(t *testing.T) {
		s := startWrapped(t, bin, "exit3")
		s.call(t, 1, "initialize")
		if code := s.wait(t, 5*time.Second); code != 3 {
			t.Fatalf("exit code %d, want 3; stderr:\n%s", code, s.stderr)
		}
	})

	t.Run("terminates a server that ignores stdin closing", func(t *testing.T) {
		s := startWrapped(t, bin, "stubborn", "--shutdown-grace=200ms")
		s.call(t, 1, "initialize")
		s.stdin.Close()
		if code := s.wait(t, 5*time.Second); code != 0 {
			t.Fatalf("exit code %d; stderr:\n%s", code, s.stderr)
		}
		if !strings.Contains(s.stderr.String(), "was terminated") {
			t.Errorf("no termination warning in stderr:\n%s", s.stderr)
		}
	})

	t.Run("writes JSON logs to a file", func(t *testing.T) {
		logFile := filepath.Join(t.TempDir(), "p.log")
		s := startWrapped(t, bin, "echo", "--log-file", logFile)
		s.call(t, 1, "ping")
		s.stdin.Close()
		s.wait(t, 5*time.Second)
		data, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"method":"ping"`) {
			t.Errorf("log file doesn't record the ping:\n%s", data)
		}
		if info, _ := os.Stat(logFile); info.Mode().Perm() != 0o600 {
			t.Errorf("log file mode %v, want 0600", info.Mode().Perm())
		}
		if strings.Contains(s.stderr.String(), "session started") {
			t.Error("logs went to stderr as well as the file")
		}
	})

	t.Run("reports a server that can't start", func(t *testing.T) {
		cmd := exec.Command(bin, "wrap", "--", "/nonexistent/server")
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != exitError || !strings.Contains(string(out), "starting /nonexistent/server") {
			t.Errorf("exit %d, output %q", cmd.ProcessState.ExitCode(), out)
		}
	})
}
