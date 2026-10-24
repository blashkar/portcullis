// Package transport starts and connects to upstream MCP servers.
package transport

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// Process is an MCP server running as a child process, spoken to over its
// stdin and stdout.
type Process struct {
	Stdin  io.WriteCloser
	Stdout io.ReadCloser

	cmd *exec.Cmd
}

// StartProcess starts command with args. The server's stderr, where MCP
// servers write their logs, goes to stderr.
//
// Cancelling ctx shuts the server down the way the MCP spec describes for
// stdio: SIGTERM first, then SIGKILL if it hasn't exited after grace.
// Closing Stdin first, which asks the server to exit on its own, is up to
// the caller.
func StartProcess(ctx context.Context, command string, args []string, stderr io.Writer, grace time.Duration) (*Process, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stderr = stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = grace

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", command, err)
	}
	return &Process{Stdin: stdin, Stdout: stdout, cmd: cmd}, nil
}

// PID is the server's process id.
func (p *Process) PID() int {
	return p.cmd.Process.Pid
}

// Wait waits for the server to exit. Call it only after Stdout has been read
// to EOF, since it closes the pipes.
func (p *Process) Wait() error {
	return p.cmd.Wait()
}

// ExitCode is the server's exit code after Wait, or -1 if a signal killed it.
func (p *Process) ExitCode() int {
	if p.cmd.ProcessState == nil {
		return -1
	}
	return p.cmd.ProcessState.ExitCode()
}
