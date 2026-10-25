// Command portcullis-agent is a chat agent that runs entirely on local
// models. It gets its tools from an MCP server, usually one wrapped by
// portcullis, and lets a model served by Ollama call them.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const (
	exitOK          = 0
	exitError       = 2
	exitInterrupted = 130 // the shell convention for "stopped by Ctrl-C" (128 + SIGINT)
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

// run is separate from main so deferred cleanup runs before os.Exit.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "\nportcullis-agent: interrupted")
		return exitInterrupted
	default:
		fmt.Fprintln(os.Stderr, "portcullis-agent:", err)
		return exitError
	}
}
