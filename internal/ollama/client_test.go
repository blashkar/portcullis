package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Chunks captured from a real Ollama 0.32 server (llama3.2:3b) asked about
// the weather with a get_weather tool available.
const toolCallStream = `{"model":"llama3.2:3b","created_at":"2026-10-25T01:26:42.301957Z","message":{"role":"assistant","content":"","tool_calls":[{"id":"call_4l13thfd","function":{"index":0,"name":"get_weather","arguments":{"city":"Paris"}}}]},"done":false}
{"model":"llama3.2:3b","created_at":"2026-10-25T01:26:42.312279Z","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","total_duration":3869888375,"load_duration":3581041292,"prompt_eval_count":157,"prompt_eval_duration":153178000,"eval_count":13,"eval_duration":129639000}
`

// newTestClient starts a fake Ollama server with handler and returns a client for it.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseHost(t *testing.T) {
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "", want: "http://127.0.0.1:11434"},
		{in: "localhost", want: "http://localhost:11434"},
		{in: "192.0.2.10:8080", want: "http://192.0.2.10:8080"},
		{in: "http://box/", want: "http://box:11434"},
		{in: "https://ollama.example.com", want: "https://ollama.example.com"},
		{in: "[::1]", want: "http://[::1]:11434"},
		{in: "ftp://box", wantErr: "scheme must be http or https"},
		{in: "http://:11434", wantErr: "missing host name"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			u, err := parseHost(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if u.String() != tt.want {
				t.Errorf("parseHost(%q) = %s, want %s", tt.in, u, tt.want)
			}
		})
	}
}

func TestChatErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		check   func(error) bool
		wantErr string
	}{
		{
			name: "model not found",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":"model 'nope' not found"}`)
			},
			check:   IsNotFound,
			wantErr: "ollama: model 'nope' not found (HTTP 404)",
		},
		{
			name: "error mid-stream",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, `{"message":{"role":"assistant","content":"Hel"},"done":false}`)
				fmt.Fprintln(w, `{"error":"out of memory"}`)
			},
			wantErr: "ollama: out of memory",
		},
		{
			name: "stream cut short",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, `{"message":{"role":"assistant","content":"Hel"},"done":false}`)
			},
			wantErr: "ended before the model finished",
		},
		{
			name: "non-JSON error page",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
			wantErr: "bad gateway (HTTP 502)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, tt.handler)
			err := c.Chat(context.Background(), ChatRequest{Model: "m"}, func(ChatResponse) error { return nil })
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.check != nil && !tt.check(err) {
				t.Errorf("error %v did not satisfy check", err)
			}
		})
	}
}

func TestChatCancelStopsStream(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"message":{"role":"assistant","content":"first"},"done":false}`)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // a slow model: never sends the rest
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	err := c.Chat(ctx, ChatRequest{Model: "m"}, func(ChatResponse) error {
		cancel() // e.g. the user pressed Ctrl-C after the first token
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("Chat did not return promptly after cancellation")
	}
}

func TestConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // nothing listens here any more

	c, err := NewClient(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Version(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is it running?") {
		t.Errorf("error = %v, want a hint to start Ollama", err)
	}
}

func TestChatToolCalls(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		fmt.Fprint(w, toolCallStream)
	})

	req := ChatRequest{
		Model:    "llama3.2:3b",
		Messages: []Message{{Role: "user", Content: "What is the weather in Paris?"}},
		Tools: []Tool{{Type: "function", Function: ToolFunction{
			Name:        "get_weather",
			Description: "Get the current weather for a city",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}},
		}}},
	}
	var calls []ToolCall
	var last ChatResponse
	err := c.Chat(context.Background(), req, func(r ChatResponse) error {
		calls = append(calls, r.Message.ToolCalls...)
		last = r
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if got["stream"] != true {
		t.Errorf("stream = %v, want true", got["stream"])
	}
	tools, _ := got["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("sent tools = %v, want one tool", got["tools"])
	}
	if fn := tools[0].(map[string]any)["function"].(map[string]any); fn["name"] != "get_weather" || fn["parameters"] == nil {
		t.Errorf("sent tool = %v", fn)
	}

	if len(calls) != 1 {
		t.Fatalf("got %d tool calls, want 1", len(calls))
	}
	call := calls[0]
	if call.ID != "call_4l13thfd" || call.Function.Name != "get_weather" || string(call.Function.Arguments) != `{"city":"Paris"}` {
		t.Errorf("tool call = %+v (arguments %s)", call, call.Function.Arguments)
	}
	if !last.Done || last.EvalCount != 13 || last.LoadDuration != 3581041292*time.Nanosecond {
		t.Errorf("final chunk = %+v", last)
	}
}

// A tool result goes back as a "tool" message naming the tool.
func TestToolMessageWireFormat(t *testing.T) {
	b, err := json.Marshal(Message{Role: "tool", ToolName: "get_weather", Content: "18C and sunny"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"role":"tool","content":"18C and sunny","tool_name":"get_weather"}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
}

func TestShowVersion(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["model"] != "llama3.2:3b" {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"error":"model '%s' not found"}`, body["model"])
				return
			}
			fmt.Fprint(w, `{"details":{"family":"llama","parameter_size":"3.2B"},"capabilities":["completion","tools"]}`)
		case "/api/version":
			fmt.Fprint(w, `{"version":"0.32.15"}`)
		}
	})
	ctx := context.Background()

	info, err := c.Show(ctx, "llama3.2:3b")
	if err != nil {
		t.Fatal(err)
	}
	if !info.SupportsTools() || info.Details.ParameterSize != "3.2B" {
		t.Errorf("Show = %+v", info)
	}
	if _, err := c.Show(ctx, "nope"); !IsNotFound(err) {
		t.Errorf("Show(nope) error = %v, want not found", err)
	}
	if v, err := c.Version(ctx); err != nil || v != "0.32.15" {
		t.Errorf("Version = %q, %v", v, err)
	}
}
