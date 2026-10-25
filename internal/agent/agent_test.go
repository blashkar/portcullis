package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blashkar/portcullis/internal/ollama"
)

// scriptedModel replies with one scripted turn per Chat call and records
// the requests it got.
type scriptedModel struct {
	turns    [][]ollama.ChatResponse
	requests []ollama.ChatRequest
}

func (m *scriptedModel) Chat(_ context.Context, req ollama.ChatRequest, fn func(ollama.ChatResponse) error) error {
	// Copy the messages: the agent appends to its history after the call.
	req.Messages = append([]ollama.Message(nil), req.Messages...)
	m.requests = append(m.requests, req)
	if len(m.turns) == 0 {
		return errors.New("scriptedModel: no more turns")
	}
	turn := m.turns[0]
	m.turns = m.turns[1:]
	for _, r := range turn {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func text(chunks ...string) []ollama.ChatResponse {
	var out []ollama.ChatResponse
	for _, c := range chunks {
		out = append(out, ollama.ChatResponse{Message: ollama.Message{Role: "assistant", Content: c}})
	}
	return append(out, ollama.ChatResponse{Done: true, Metrics: ollama.Metrics{EvalCount: len(chunks)}})
}

func calls(cs ...ollama.ToolCall) []ollama.ChatResponse {
	return []ollama.ChatResponse{
		{Message: ollama.Message{Role: "assistant", ToolCalls: cs}},
		{Done: true},
	}
}

func call(name, args string) ollama.ToolCall {
	return ollama.ToolCall{Function: ollama.ToolCallFunction{Name: name, Arguments: json.RawMessage(args)}}
}

// fakeTools answers calls from a map of tool name to result.
type fakeTools struct {
	results map[string]Result
	err     error
	got     []string // "name args" for each call
}

func (f *fakeTools) CallTool(_ context.Context, name string, args json.RawMessage) (Result, error) {
	f.got = append(f.got, name+" "+string(args))
	if f.err != nil {
		return Result{}, f.err
	}
	return f.results[name], nil
}

func tool(name string) ollama.Tool {
	return ollama.Tool{Type: "function", Function: ollama.ToolFunction{Name: name, Parameters: map[string]any{"type": "object"}}}
}

func TestAskWithoutTools(t *testing.T) {
	model := &scriptedModel{turns: [][]ollama.ChatResponse{text("Hello", " there")}}
	var tokens []string
	a := &Agent{Model: "m", Chat: model, Caller: &fakeTools{}, Events: Events{Token: func(s string) { tokens = append(tokens, s) }}}

	answer, err := a.Ask(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if answer != "Hello there" || strings.Join(tokens, "|") != "Hello| there" {
		t.Errorf("answer %q, tokens %q", answer, tokens)
	}
	req := model.requests[0]
	if req.Model != "m" || len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[0].Content != DefaultSystemPrompt {
		t.Errorf("first request = %+v", req)
	}
}

func TestAskRunsToolsAndFeedsResultsBack(t *testing.T) {
	model := &scriptedModel{turns: [][]ollama.ChatResponse{
		calls(call("list_dir", `{"path":"/w"}`), call("read_file", `{"path":"/w/a.txt"}`)),
		text("The file says hi."),
	}}
	tools := &fakeTools{results: map[string]Result{
		"list_dir":  {Text: "a.txt"},
		"read_file": {Text: "hi"},
	}}
	var events []string
	var steps []int
	a := &Agent{
		Model:  "m",
		Chat:   model,
		Tools:  []ollama.Tool{tool("list_dir"), tool("read_file")},
		Caller: tools,
		System: "be brief",
		Events: Events{
			ToolCall:   func(name string, args []byte) { events = append(events, "call "+name+" "+string(args)) },
			ToolResult: func(name string, r Result) { events = append(events, "result "+name+" "+r.Text) },
			Step:       func(step int, _ ollama.Metrics) { steps = append(steps, step) },
		},
	}

	answer, err := a.Ask(context.Background(), "what's in a.txt?")
	if err != nil {
		t.Fatal(err)
	}
	if answer != "The file says hi." {
		t.Errorf("answer = %q", answer)
	}
	wantEvents := []string{
		`call list_dir {"path":"/w"}`, "result list_dir a.txt",
		`call read_file {"path":"/w/a.txt"}`, "result read_file hi",
	}
	if strings.Join(events, "\n") != strings.Join(wantEvents, "\n") {
		t.Errorf("events:\n%s\nwant:\n%s", strings.Join(events, "\n"), strings.Join(wantEvents, "\n"))
	}
	if len(steps) != 2 {
		t.Errorf("steps = %v, want [1 2]", steps)
	}

	// The second model call sees the tool calls and both results.
	second := model.requests[1]
	if len(second.Tools) != 2 {
		t.Errorf("tools offered = %d, want 2", len(second.Tools))
	}
	roles := []string{}
	for _, m := range second.Messages {
		roles = append(roles, m.Role+":"+m.ToolName)
	}
	if got, want := strings.Join(roles, " "), "system: user: assistant: tool:list_dir tool:read_file"; got != want {
		t.Errorf("messages = %s, want %s", got, want)
	}
	if second.Messages[0].Content != "be brief" || second.Messages[4].Content != "hi" {
		t.Errorf("system or tool content wrong: %+v", second.Messages)
	}
	if len(a.History()) != 6 {
		t.Errorf("history has %d messages, want 6", len(a.History()))
	}
}

func TestToolErrorsGoToTheModel(t *testing.T) {
	model := &scriptedModel{turns: [][]ollama.ChatResponse{
		calls(call("read_file", `{"path":"/etc/shadow"}`), call("made_up", `{}`)),
		text("I can't read that."),
	}}
	tools := &fakeTools{results: map[string]Result{"read_file": {Text: "access denied", IsError: true}}}
	a := &Agent{Model: "m", Chat: model, Tools: []ollama.Tool{tool("read_file")}, Caller: tools}

	if _, err := a.Ask(context.Background(), "read /etc/shadow"); err != nil {
		t.Fatal(err)
	}
	msgs := model.requests[1].Messages
	if got := msgs[len(msgs)-2].Content; got != "error: access denied" {
		t.Errorf("tool error sent as %q", got)
	}
	if got := msgs[len(msgs)-1].Content; !strings.Contains(got, `no tool named "made_up"`) {
		t.Errorf("unknown tool reported as %q", got)
	}
	if len(tools.got) != 1 {
		t.Errorf("server got %v; an unknown tool must not reach it", tools.got)
	}
}

func TestAskStopsAfterMaxSteps(t *testing.T) {
	loop := calls(call("ping", `{}`))
	model := &scriptedModel{turns: [][]ollama.ChatResponse{loop, loop, loop, loop}}
	a := &Agent{Model: "m", Chat: model, Tools: []ollama.Tool{tool("ping")}, Caller: &fakeTools{}, MaxSteps: 3}

	_, err := a.Ask(context.Background(), "go")
	if !errors.Is(err, ErrTooManySteps) {
		t.Fatalf("err = %v, want ErrTooManySteps", err)
	}
	if len(model.requests) != 3 {
		t.Errorf("model called %d times, want 3", len(model.requests))
	}
}

func TestBrokenToolsStopTheAgent(t *testing.T) {
	model := &scriptedModel{turns: [][]ollama.ChatResponse{calls(call("ping", `{}`))}}
	a := &Agent{Model: "m", Chat: model, Tools: []ollama.Tool{tool("ping")}, Caller: &fakeTools{err: errors.New("connection closed")}}

	_, err := a.Ask(context.Background(), "go")
	if err == nil || !strings.Contains(err.Error(), "calling tool ping: connection closed") {
		t.Fatalf("err = %v", err)
	}
}

func TestConversationContinuesAndResets(t *testing.T) {
	model := &scriptedModel{turns: [][]ollama.ChatResponse{text("one"), text("two"), text("three")}}
	a := &Agent{Model: "m", Chat: model, Caller: &fakeTools{}}
	ctx := context.Background()

	for _, q := range []string{"first", "second"} {
		if _, err := a.Ask(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(model.requests[1].Messages); n != 4 { // system, first, one, second
		t.Errorf("second request has %d messages, want 4", n)
	}
	a.Reset()
	if _, err := a.Ask(ctx, "third"); err != nil {
		t.Fatal(err)
	}
	if n := len(model.requests[2].Messages); n != 2 {
		t.Errorf("after Reset the request has %d messages, want 2", n)
	}
}
