package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/pin"
)

type pinOptions struct {
	configPath string
	file       string
	all        bool
}

func newPinCmd() *cobra.Command {
	var opts pinOptions
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Review and approve tool definitions",
		Long: `portcullis serve pins each tool's definition the first time it sees it. If a
server later changes a tool's description or schema, the tool is held back
until you review the change and approve it. These commands do that; a
running serve picks up approvals within a few seconds.`,
		Example: `  portcullis pin list
  portcullis pin diff fs__read_file
  portcullis pin approve fs__read_file`,
	}
	pf := cmd.PersistentFlags()
	pf.StringVarP(&opts.configPath, "config", "c", "portcullis.yaml", "config file, used to find the pin file")
	pf.StringVar(&opts.file, "file", "", "pin file (default: the one in the config file)")

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List pinned tools and changes waiting for approval",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runPinList(cmd.OutOrStdout(), opts)
			},
		},
		&cobra.Command{
			Use:   "diff [tool...]",
			Short: "Show what changed in tools waiting for approval",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runPinDiff(cmd.OutOrStdout(), opts, args)
			},
		},
	)
	approve := &cobra.Command{
		Use:   "approve [tool...]",
		Short: "Approve the current definitions of tools waiting for approval",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPinApprove(cmd.OutOrStdout(), opts, args)
		},
	}
	approve.Flags().BoolVar(&opts.all, "all", false, "approve every tool waiting for approval")
	cmd.AddCommand(approve)
	return cmd
}

// openPins opens an existing pin file; it never creates one.
func openPins(opts pinOptions) (*pin.Store, error) {
	path := opts.file
	if path == "" {
		cfg, err := config.Load(opts.configPath)
		if err != nil {
			return nil, fmt.Errorf("finding the pin file (or pass --file): %w", err)
		}
		if path = cfg.PinsPath(); path == "" {
			return nil, fmt.Errorf("%s turns pinning off", opts.configPath)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no pin file at %s: %w", path, err)
	}
	return pin.Open(path, false), nil
}

func runPinList(out io.Writer, opts pinOptions) error {
	store, err := openPins(opts)
	if err != nil {
		return err
	}
	entries, err := store.Entries()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tSTATUS\tAPPROVED\tCHANGE SEEN")
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		e := entries[name]
		status, approved, seen := "approved", "-", "-"
		if !e.Approved.IsZero() {
			approved = e.Approved.Local().Format(time.DateTime)
		}
		if e.Pending != nil {
			seen = e.Pending.Seen.Local().Format(time.DateTime)
			status = "changed: waiting"
			if e.Hash == "" {
				status = "new: waiting"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", clean(name), status, approved, seen)
	}
	return tw.Flush()
}

func runPinDiff(out io.Writer, opts pinOptions, names []string) error {
	store, err := openPins(opts)
	if err != nil {
		return err
	}
	entries, err := store.Entries()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			if entries[name].Pending != nil {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			fmt.Fprintln(out, "nothing is waiting for approval")
			return nil
		}
	}
	var errs []error
	for i, name := range names {
		e := entries[name]
		if e == nil || e.Pending == nil {
			errs = append(errs, fmt.Errorf("%s: nothing waiting for approval", name))
			continue
		}
		if i > 0 {
			fmt.Fprintln(out)
		}
		var old []string
		if e.Definition != nil {
			old = e.Definition.Lines()
			fmt.Fprintf(out, "%s: changed (seen %s)\n", clean(name), e.Pending.Seen.Local().Format(time.DateTime))
		} else {
			fmt.Fprintf(out, "%s: new (seen %s)\n", clean(name), e.Pending.Seen.Local().Format(time.DateTime))
		}
		for _, line := range pin.Trim(pin.Diff(old, e.Pending.Definition.Lines()), 3) {
			fmt.Fprintln(out, clean(line))
		}
	}
	return errors.Join(errs...)
}

func runPinApprove(out io.Writer, opts pinOptions, names []string) error {
	if len(names) == 0 && !opts.all {
		return errors.New("name the tools to approve, or pass --all")
	}
	if len(names) > 0 && opts.all {
		return errors.New("name tools or pass --all, not both")
	}
	store, err := openPins(opts)
	if err != nil {
		return err
	}
	approved, err := store.Approve(names)
	if len(approved) > 0 {
		fmt.Fprintf(out, "approved %s\n", strings.Join(approved, ", "))
	} else if err == nil {
		fmt.Fprintln(out, "nothing is waiting for approval")
	}
	return err
}
