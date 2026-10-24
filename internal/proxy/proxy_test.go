package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/jsonrpc"
)

// syncBuffer is a bytes.Buffer that's safe to write from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeServer answers every request with {"echo": method}. It first sends the
// client a roots/list request, as a real server might, and exits when its
// stdin closes.
func fakeServer(t *testing.T, in io.Reader, out io.WriteCloser) {
	defer out.Close()
	w := jsonrpc.NewWriter(out)
	if err := w.Write([]byte(`{"jsonrpc":"2.0","id":"s1","method":"roots/list"}`)); err != nil {
		t.Error(err)
		return
	}
	r := jsonrpc.NewReader(in, 0)
	for {
		raw, err := r.Read()
		if err != nil {
			return
		}
		msg, err := jsonrpc.Parse(raw)
		if err != nil || msg.Kind() != jsonrpc.KindRequest {
			continue
		}
		reply := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"echo":%q}}`, msg.ID, msg.Method)
		if err := w.Write([]byte(reply)); err != nil {
			t.Error(err)
			return
		}
	}
}

func TestRun(t *testing.T) {
	clientInR, clientInW := io.Pipe()
	clientOutR, clientOutW := io.Pipe()
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()
	go fakeServer(t, serverInR, serverOutW)

	var logs syncBuffer
	clientClosed := make(chan struct{})
	p := &Proxy{
		Logger:        slog.New(slog.NewJSONHandler(&logs, nil)),
		OnClientClose: func() { close(clientClosed) },
	}

	type result struct {
		stats Stats
		err   error
	}
	done := make(chan result)
	go func() {
		stats, err := p.Run(Endpoints{ClientIn: clientInR, ClientOut: clientOutW, ServerIn: serverInW, ServerOut: serverOutR})
		done <- result{stats, err}
	}()

	fromProxy := bufio.NewScanner(clientOutR)
	expectLine := func(want string) {
		t.Helper()
		if !fromProxy.Scan() {
			t.Fatalf("client stream ended, want %s", want)
		}
		if got := fromProxy.Text(); got != want {
			t.Fatalf("client got %s\nwant %s", got, want)
		}
	}
	send := func(line string) {
		t.Helper()
		if _, err := io.WriteString(clientInW, line+"\n"); err != nil {
			t.Fatal(err)
		}
	}

	// Server-initiated request, forwarded unchanged.
	expectLine(`{"jsonrpc":"2.0","id":"s1","method":"roots/list"}`)

	// Odd spacing checks that messages are forwarded byte for byte, not re-encoded.
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize",  "params":{}}`)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":"s1","result":{"roots":[]}}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`)
	send(`not json`)

	expectLine(`{"jsonrpc":"2.0","id":1,"result":{"echo":"initialize"}}`)
	expectLine(`{"jsonrpc":"2.0","id":2,"result":{"echo":"tools/call"}}`)

	clientInW.Close()
	var res result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after the server exited")
	}
	clientOutW.Close()
	if res.err != nil {
		t.Fatalf("Run: %v", res.err)
	}
	select {
	case <-clientClosed:
	case <-time.After(time.Second):
		t.Fatal("OnClientClose wasn't called")
	}

	want := Stats{ClientToServer: 5, ServerToClient: 3, Invalid: 1}
	if res.stats != want {
		t.Errorf("stats = %+v, want %+v", res.stats, want)
	}

	records := parseLogs(t, logs.String())
	// Responses are matched to their requests in both directions.
	wantResponses := []struct{ dir, id, method, tool string }{
		{"server->client", "1", "initialize", ""},
		{"client->server", `"s1"`, "roots/list", ""},
		{"server->client", "2", "tools/call", "read_file"},
	}
	for _, w := range wantResponses {
		found := false
		for _, r := range records {
			if r["kind"] == "response" && r["dir"] == w.dir && r["id"] == w.id {
				found = true
				if r["method"] != w.method || (w.tool != "" && r["tool"] != w.tool) || r["duration"] == nil {
					t.Errorf("response %s logged as %v, want method %s, tool %q and a duration", w.id, r, w.method, w.tool)
				}
			}
		}
		if !found {
			t.Errorf("no log record for the response to %s", w.id)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"invalid message"`) {
		t.Error("the invalid message wasn't logged")
	}
	if strings.Contains(logs.String(), "/tmp/x") {
		t.Error("payload logged although PayloadLimit is 0")
	}
}

func TestRunDropsOversizedMessages(t *testing.T) {
	big := `{"jsonrpc":"2.0","method":"x","params":"` + strings.Repeat("a", 5000) + `"}`
	clientIn := strings.NewReader(big + "\n" + `{"jsonrpc":"2.0","method":"small"}` + "\n")
	serverIn := &closeBuffer{}

	p := &Proxy{MaxMessageSize: 1000}
	stats, err := p.Run(Endpoints{
		ClientIn:  clientIn,
		ClientOut: io.Discard,
		ServerIn:  serverIn,
		// The server side ends once the client side is done, like a server
		// exiting when its stdin closes.
		ServerOut: serverIn.waitClosed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Dropped != 1 || stats.ClientToServer != 1 {
		t.Errorf("stats = %+v, want 1 dropped and 1 forwarded", stats)
	}
	if got := serverIn.String(); got != `{"jsonrpc":"2.0","method":"small"}`+"\n" {
		t.Errorf("server got %q", got)
	}
}

func TestPayloadLogging(t *testing.T) {
	var logs syncBuffer
	p := &Proxy{Logger: slog.New(slog.NewJSONHandler(&logs, nil)), PayloadLimit: 20}
	p.inspect(ClientToServer, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	r := parseLogs(t, logs.String())[0]
	if r["payload"] != `{"jsonrpc":"2.0","me…` {
		t.Errorf("payload = %q", r["payload"])
	}
}

// closeBuffer records what's written to it and signals when it's closed.
type closeBuffer struct {
	syncBuffer
	once   sync.Once
	closed chan struct{}
}

func (b *closeBuffer) Close() error {
	b.once.Do(func() { close(b.ch()) })
	return nil
}

func (b *closeBuffer) ch() chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed == nil {
		b.closed = make(chan struct{})
	}
	return b.closed
}

// waitClosed returns a reader that blocks until b is closed, then reports EOF.
func (b *closeBuffer) waitClosed() io.Reader {
	r, w := io.Pipe()
	go func() {
		<-b.ch()
		w.Close()
	}()
	return r
}

func parseLogs(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(s) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}
