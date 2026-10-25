package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/ollama"
)

// MCPTools adapts an MCP client session to the agent: it lists the server's
// tools in Ollama's format and runs tool calls on the server.
type MCPTools struct {
	Session *mcp.ClientSession
}

// List returns every tool the server offers, as Ollama tool definitions.
func (m *MCPTools) List(ctx context.Context) ([]ollama.Tool, error) {
	var tools []ollama.Tool
	for t, err := range m.Session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("listing tools: %w", err)
		}
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		tools = append(tools, ollama.Tool{
			Type:     "function",
			Function: ollama.ToolFunction{Name: t.Name, Description: t.Description, Parameters: schema},
		})
	}
	return tools, nil
}

// CallTool runs a tool on the server. The server's own errors, and JSON-RPC
// errors such as a proxy refusing the call, come back as Result.IsError so the
// model can see them. Only a closed connection is returned as an error.
func (m *MCPTools) CallTool(ctx context.Context, name string, args json.RawMessage) (Result, error) {
	params := &mcp.CallToolParams{Name: name, Arguments: arguments(args)}
	res, err := m.Session.CallTool(ctx, params)
	switch {
	case errors.Is(err, mcp.ErrConnectionClosed), ctx.Err() != nil:
		return Result{}, err
	case err != nil:
		return Result{Text: err.Error(), IsError: true}, nil
	}
	return Result{Text: resultText(res), IsError: res.IsError}, nil
}

// arguments turns the model's arguments into a JSON object. Models send
// null or nothing for tools that take no arguments.
func arguments(raw json.RawMessage) any {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}
	}
	return raw
}

// resultText flattens a tool result into text the model can read.
func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			parts = append(parts, c.Text)
		case *mcp.ImageContent:
			parts = append(parts, fmt.Sprintf("[image: %s, %d bytes]", c.MIMEType, len(c.Data)))
		case *mcp.AudioContent:
			parts = append(parts, fmt.Sprintf("[audio: %s, %d bytes]", c.MIMEType, len(c.Data)))
		case *mcp.ResourceLink:
			parts = append(parts, fmt.Sprintf("[resource: %s]", c.URI))
		case *mcp.EmbeddedResource:
			if c.Resource != nil && c.Resource.Text != "" {
				parts = append(parts, c.Resource.Text)
			} else if c.Resource != nil {
				parts = append(parts, fmt.Sprintf("[resource: %s]", c.Resource.URI))
			}
		}
	}
	if len(parts) == 0 && res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			parts = append(parts, string(b))
		}
	}
	return strings.Join(parts, "\n")
}
