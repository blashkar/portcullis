// Command portcullis is a security proxy for MCP servers. It sits between an
// AI agent and the servers that give it tools, and sees every message.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Exit codes. When portcullis wraps a server it exits with the server's own
// code, so these only cover portcullis's failures.
const (
	exitOK          = 0
	exitError       = 2
	exitInterrupted = 130 // the shell convention for "stopped by Ctrl-C" (128 + SIGINT)
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// exitCodeError makes the process exit with code without printing anything.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

func main() {
	os.Exit(run())
}

// run is separate from main so deferred cleanup runs before os.Exit.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)
	var exit exitCodeError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &exit):
		return exit.code
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "portcullis: interrupted")
		return exitInterrupted
	default:
		fmt.Fprintln(os.Stderr, "portcullis:", err)
		return exitError
	}
}
