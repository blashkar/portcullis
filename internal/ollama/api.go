package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"
)

// Message is one turn of a chat conversation.
type Message struct {
	Role    string `json:"role"` // "system", "user", "assistant" or "tool"
	Content string `json:"content"`
	// Thinking is a reasoning model's thinking, which Ollama streams
	// separately from Content.
	Thinking string `json:"thinking,omitempty"`
	// ToolCalls are the tools an assistant message asks to call.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolName names the tool whose result a "tool" message carries.
	ToolName string `json:"tool_name,omitempty"`
}

// Tool describes a function the model may call.
type Tool struct {
	Type     string       `json:"type"` // always "function"
	Function ToolFunction `json:"function"`
}

// ToolFunction is a tool's name, description and JSON Schema for its arguments.
type ToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters"`
}

// ToolCall is one call the model wants made.
type ToolCall struct {
	ID       string           `json:"id,omitempty"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction is the tool to call and its arguments. Ollama sends the
// arguments as a JSON object, not as a string the way OpenAI does.
type ToolCallFunction struct {
	Index     int             `json:"index,omitempty"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ChatRequest asks a model to continue a conversation.
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []Tool    `json:"tools,omitempty"`
	// Options are model parameters such as temperature, seed and num_ctx.
	Options map[string]any `json:"options,omitempty"`
}

// ChatResponse is one chunk of a streamed chat response. The final chunk has
// Done set and carries the Metrics for the whole response.
type ChatResponse struct {
	Model      string    `json:"model"`
	CreatedAt  time.Time `json:"created_at"`
	Message    Message   `json:"message"`
	Done       bool      `json:"done"`
	DoneReason string    `json:"done_reason,omitempty"`
	Metrics
}

// Metrics are the token counts and timings Ollama reports when a response is done.
// Ollama sends durations in nanoseconds, which decode directly into time.Duration.
type Metrics struct {
	TotalDuration      time.Duration `json:"total_duration"`
	LoadDuration       time.Duration `json:"load_duration"`
	PromptEvalCount    int           `json:"prompt_eval_count"`
	PromptEvalDuration time.Duration `json:"prompt_eval_duration"`
	EvalCount          int           `json:"eval_count"`
	EvalDuration       time.Duration `json:"eval_duration"`
}

// chatRequest is the wire format; Chat always streams.
type chatRequest struct {
	ChatRequest
	Stream bool `json:"stream"`
}

// Chat streams a chat response, calling fn for each chunk as it arrives.
// Tool calls arrive in their own chunks, alongside the streamed content.
// It returns an error if the stream ends before the model is done.
func (c *Client) Chat(ctx context.Context, req ChatRequest, fn func(ChatResponse) error) error {
	resp, err := c.do(ctx, http.MethodPost, "/api/chat", chatRequest{ChatRequest: req, Stream: true})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	done := false
	err = stream(resp.Body, func(r ChatResponse) error {
		done = r.Done
		return fn(r)
	})
	if err != nil {
		return err
	}
	if !done {
		return errors.New("ollama: response ended before the model finished")
	}
	return nil
}

// ModelDetails describes a model's architecture and quantization.
type ModelDetails struct {
	Format            string `json:"format"`
	Family            string `json:"family"`
	ParameterSize     string `json:"parameter_size"`
	QuantizationLevel string `json:"quantization_level"`
}

// ShowResponse describes one installed model.
type ShowResponse struct {
	Details      ModelDetails `json:"details"`
	Capabilities []string     `json:"capabilities"`
	ModifiedAt   time.Time    `json:"modified_at"`
}

// SupportsTools reports whether the model can call tools.
func (s *ShowResponse) SupportsTools() bool {
	return slices.Contains(s.Capabilities, "tools")
}

// Show returns details about model. If the model is not installed, the
// error satisfies IsNotFound.
func (c *Client) Show(ctx context.Context, model string) (*ShowResponse, error) {
	var out ShowResponse
	if err := c.getJSON(ctx, http.MethodPost, "/api/show", map[string]string{"model": model}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Version returns the server's version. It is a cheap way to check that the
// server is reachable.
func (c *Client) Version(ctx context.Context) (string, error) {
	var body struct {
		Version string `json:"version"`
	}
	if err := c.getJSON(ctx, http.MethodGet, "/api/version", nil, &body); err != nil {
		return "", err
	}
	return body.Version, nil
}
