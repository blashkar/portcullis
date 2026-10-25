package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/agent"
	"github.com/blashkar/portcullis/internal/ollama"
)

const defaultModel = "llama3.2:3b"

type options struct {
	model        string
	ollamaHost   string
	prompt       string
	system       string
	maxSteps     int
	numCtx       int
	temperature  float64
	serverStderr string
	connectWait  time.Duration
}

func newRootCmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:   "portcullis-agent [flags] -- <MCP server command> [args...]",
		Short: "A local tool-calling agent for MCP servers",
		Long: `portcullis-agent is a chat agent that runs on a local model through Ollama.
It starts an MCP server, offers the server's tools to the model, and runs
the tool calls the model makes.

To see and control what the model does, start the server through portcullis:
put "portcullis wrap --" in front of the server's command.`,
		Example: `  portcullis-agent -- portcullis wrap --log-file portcullis.log -- sandbox/run.sh filesystem

  portcullis-agent -m llama3.2:3b -p "Which files are in the project?" -- portcullis wrap -- ./my-server`,
		Version:       version,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var temperature *float64
			if cmd.Flags().Changed("temperature") {
				temperature = &opts.temperature
			}
			return runAgent(cmd.Context(), opts, temperature, args)
		},
	}
	// Stop parsing flags at the server command, so its flags stay its own.
	cmd.Flags().SetInterspersed(false)

	f := cmd.Flags()
	f.StringVarP(&opts.model, "model", "m", defaultModel, "Ollama model to use; it must support tool calling")
	f.StringVar(&opts.ollamaHost, "ollama-host", "", "Ollama server (default $OLLAMA_HOST or "+ollama.DefaultHost+")")
	f.StringVarP(&opts.prompt, "prompt", "p", "", "ask one question, print the answer and exit")
	f.StringVar(&opts.system, "system", "", "replace the default system prompt")
	f.IntVar(&opts.maxSteps, "max-steps", agent.DefaultMaxSteps, "most model calls per question")
	f.IntVar(&opts.numCtx, "num-ctx", 16384, "context window in tokens; tool definitions take space (0 = Ollama's default)")
	f.Float64Var(&opts.temperature, "temperature", 0, "sampling temperature (default: the model's own)")
	f.StringVar(&opts.serverStderr, "server-stderr", "", "write the MCP server's stderr to this file (default: discard, but show it if startup fails)")
	f.DurationVar(&opts.connectWait, "connect-timeout", 2*time.Minute, "how long the MCP server gets to start")
	return cmd
}

func runAgent(ctx context.Context, opts options, temperature *float64, args []string) error {
	client, err := ollama.NewClient(firstNonEmpty(opts.ollamaHost, os.Getenv("OLLAMA_HOST")), nil)
	if err != nil {
		return err
	}
	if err := checkModel(ctx, client, opts.model); err != nil {
		return err
	}

	session, err := connect(ctx, opts, args)
	if err != nil {
		return err
	}
	defer session.Close()

	mcpTools := &agent.MCPTools{Session: session}
	tools, err := mcpTools.List(ctx)
	if err != nil {
		return err
	}

	modelOptions := map[string]any{}
	if opts.numCtx > 0 {
		modelOptions["num_ctx"] = opts.numCtx
	}
	if temperature != nil {
		modelOptions["temperature"] = *temperature
	}
	ui := newConsole(os.Stdout, os.Stderr)
	a := &agent.Agent{
		Model:    opts.model,
		Chat:     client,
		Tools:    tools,
		Caller:   mcpTools,
		System:   opts.system,
		Options:  modelOptions,
		MaxSteps: opts.maxSteps,
		Events:   ui.events(),
	}

	if opts.prompt != "" {
		return ui.ask(ctx, a, opts.prompt)
	}
	ui.status("%s with %d tools from %s. Type /help for commands.", opts.model, len(tools), serverName(session))
	return repl(ctx, a, ui, os.Stdin)
}

// checkModel fails early, with a fix, if the model is missing or can't call tools.
func checkModel(ctx context.Context, client *ollama.Client, model string) error {
	info, err := client.Show(ctx, model)
	if ollama.IsNotFound(err) {
		return fmt.Errorf("model %s isn't installed; run `ollama pull %s`", model, model)
	}
	if err != nil {
		return err
	}
	if !info.SupportsTools() {
		return fmt.Errorf("model %s doesn't support tool calling; try %s or another model with the \"tools\" capability", model, defaultModel)
	}
	return nil
}

// connect starts the MCP server and opens a session with it.
func connect(ctx context.Context, opts options, args []string) (*mcp.ClientSession, error) {
	// Keep the end of the server's stderr so a failed start can be explained.
	tail := &tailBuffer{max: 4 << 10}
	var stderr io.Writer = tail
	if opts.serverStderr != "" {
		f, err := os.OpenFile(opts.serverStderr, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("opening --server-stderr file: %w", err)
		}
		// Closed when the process exits; the agent runs one session.
		stderr = io.MultiWriter(f, tail)
	}

	server := exec.Command(args[0], args[1:]...)
	server.Stderr = stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "portcullis-agent", Version: version}, nil)

	connectCtx, cancel := context.WithTimeout(ctx, opts.connectWait)
	defer cancel()
	session, err := client.Connect(connectCtx, &mcp.CommandTransport{Command: server}, nil)
	if err != nil {
		if out := strings.TrimSpace(tail.String()); out != "" {
			return nil, fmt.Errorf("starting the MCP server: %w\nserver output:\n%s", err, out)
		}
		return nil, fmt.Errorf("starting the MCP server: %w", err)
	}
	return session, nil
}

func serverName(s *mcp.ClientSession) string {
	if res := s.InitializeResult(); res != nil && res.ServerInfo != nil && res.ServerInfo.Name != "" {
		return res.ServerInfo.Name
	}
	return "the MCP server"
}

// repl reads questions from in until EOF or /quit.
func repl(ctx context.Context, a *agent.Agent, ui *console, in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for {
		ui.promptMarker()
		if !scanner.Scan() {
			ui.newline()
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "":
			continue
		case "/quit", "/exit":
			return nil
		case "/reset":
			a.Reset()
			ui.status("Conversation cleared.")
			continue
		case "/tools":
			for _, t := range a.Tools {
				ui.status("  %s: %s", t.Function.Name, firstLine(t.Function.Description))
			}
			continue
		case "/help":
			ui.status("/tools lists the tools, /reset clears the conversation, /quit exits (or Ctrl-D).")
			continue
		}
		if err := ui.ask(ctx, a, line); err != nil {
			if errors.Is(err, agent.ErrTooManySteps) {
				ui.status("Stopped: %v.", err)
				continue
			}
			return err
		}
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
