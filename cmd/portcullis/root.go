package main

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "portcullis",
		Short: "A security proxy for MCP servers",
		Long: `portcullis sits between an AI agent and the MCP servers that give it tools.
It sees every JSON-RPC message in both directions, logs it, and with
"serve" records it in an audit log.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newWrapCmd(), newServeCmd(), newAuditCmd(), newPinCmd(), newDashboardCmd())
	return root
}
