package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/blashkar/portcullis/internal/agent"
)

// console prints the conversation. The model's answers go to out (stdout),
// and everything else (tool calls, status lines, the prompt) goes to info
// (stderr), so `-p` output can be piped on its own.
type console struct {
	out, info io.Writer
	// midLine is true while an answer is streaming and the cursor isn't at
	// the start of a line.
	midLine bool
}

func newConsole(out, info io.Writer) *console {
	return &console{out: out, info: info}
}

func (c *console) events() agent.Events {
	return agent.Events{
		Token: func(text string) {
			fmt.Fprint(c.out, text)
			c.midLine = !strings.HasSuffix(text, "\n")
		},
		ToolCall: func(name string, args []byte) {
			c.endLine()
			fmt.Fprintf(c.info, "  -> %s %s\n", name, preview(string(args), 200))
		},
		ToolResult: func(name string, r agent.Result) {
			if r.IsError {
				fmt.Fprintf(c.info, "  <- %s failed: %s\n", name, preview(r.Text, 200))
				return
			}
			fmt.Fprintf(c.info, "  <- %s: %d bytes: %s\n", name, len(r.Text), preview(r.Text, 80))
		},
	}
}

// ask runs one question and finishes the answer's line.
func (c *console) ask(ctx context.Context, a *agent.Agent, prompt string) error {
	_, err := a.Ask(ctx, prompt)
	c.endLine()
	return err
}

func (c *console) status(format string, args ...any) {
	c.endLine()
	fmt.Fprintf(c.info, format+"\n", args...)
}

func (c *console) promptMarker() {
	fmt.Fprint(c.info, "> ")
}

func (c *console) newline() {
	fmt.Fprintln(c.info)
}

func (c *console) endLine() {
	if c.midLine {
		fmt.Fprintln(c.out)
		c.midLine = false
	}
}

// preview shortens s to one line of at most n runes.
func preview(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = t.buf[over:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
