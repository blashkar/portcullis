package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type readArgs struct {
	Path string `json:"path" jsonschema:"the file to read"`
}

// connectTestServer runs an MCP server in memory and returns a client
// session for it.
func connectTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "read_file", Description: "Read a file"},
		func(_ context.Context, _ *mcp.CallToolRequest, in readArgs) (*mcp.CallToolResult, any, error) {
			if strings.HasPrefix(in.Path, "/secret") {
				return nil, nil, errors.New("access denied")
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "contents of " + in.Path}}}, nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "now", Description: "Current time"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct {
			Time string `json:"time"`
		}, error,
		) {
			return nil, struct {
				Time string `json:"time"`
			}{"12:00"}, nil
		})

	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestMCPToolsList(t *testing.T) {
	m := &MCPTools{Session: connectTestServer(t)}
	tools, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(tools))
	}
	read := tools[0]
	if read.Function.Name != "read_file" {
		read = tools[1]
	}
	if read.Type != "function" || read.Function.Description != "Read a file" {
		t.Errorf("tool = %+v", read)
	}
	schema, _ := json.Marshal(read.Function.Parameters)
	if !strings.Contains(string(schema), `"path"`) || !strings.Contains(string(schema), "the file to read") {
		t.Errorf("schema = %s", schema)
	}
}

func TestMCPToolsCall(t *testing.T) {
	m := &MCPTools{Session: connectTestServer(t)}
	ctx := context.Background()

	tests := []struct {
		name, tool, args string
		want             Result
	}{
		{name: "text result", tool: "read_file", args: `{"path":"/w/a.txt"}`, want: Result{Text: "contents of /w/a.txt"}},
		{name: "tool error", tool: "read_file", args: `{"path":"/secret"}`, want: Result{Text: "access denied", IsError: true}},
		{name: "structured result, null args", tool: "now", args: `null`, want: Result{Text: `{"time":"12:00"}`}},
		{name: "missing args", tool: "now", args: ``, want: Result{Text: `{"time":"12:00"}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.CallTool(ctx, tt.tool, json.RawMessage(tt.args))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	// Bad arguments are the model's mistake to fix, not a reason to stop.
	got, err := m.CallTool(ctx, "read_file", json.RawMessage(`{"path":42}`))
	if err != nil || !got.IsError {
		t.Errorf("bad arguments: got %+v, %v; want a tool error", got, err)
	}
}

func TestMCPToolsClosedSession(t *testing.T) {
	cs := connectTestServer(t)
	_ = cs.Close()
	_, err := (&MCPTools{Session: cs}).CallTool(context.Background(), "now", nil)
	if err == nil {
		t.Fatal("want an error from a closed session")
	}
}
