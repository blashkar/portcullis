package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/gateway"
)

// recorders sends each audit event to several recorders.
type recorders []gateway.Recorder

func (rs recorders) Record(ctx context.Context, e audit.Event) error {
	var errs []error
	for _, r := range rs {
		errs = append(errs, r.Record(ctx, e))
	}
	return errors.Join(errs...)
}

// listenDashboard opens the dashboard's listener. If the configured port is
// taken, say by another portcullis session, it falls back to a free port on
// the same address.
func listenDashboard(addr string, log *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	host, _, _ := net.SplitHostPort(addr)
	ln, err2 := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err2 != nil {
		return nil, err
	}
	log.Warn("the dashboard's port is taken; using another", "addr", addr, "err", err, "using", ln.Addr().String())
	return ln, nil
}

// writeURLFile saves the dashboard's URL for "portcullis dashboard". The URL
// holds the token, so the file is readable only by its owner, and it is
// written whole or not at all.
func writeURLFile(path, u string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".portcullis-dashboard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// CreateTemp makes the file 0600.
	if _, err := f.WriteString(u + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// removeURLFile removes the URL file if it still holds this session's URL;
// another session may have started since and replaced it.
func removeURLFile(path, u string) {
	if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == u {
		_ = os.Remove(path)
	}
}

// withoutToken returns the dashboard's URL with the token hidden, for logs.
func withoutToken(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "the dashboard"
	}
	return p.Scheme + "://" + p.Host + "/…/"
}

type dashboardOptions struct {
	configPath string
	open       bool
}

func newDashboardCmd() *cobra.Command {
	var opts dashboardOptions
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Print the running dashboard's URL, or open it",
		Long: `dashboard prints the URL of the dashboard that "portcullis serve" is running,
where calls a policy rule says need approval wait for a decision. The URL
holds a random token made when serve started; anyone with it can approve
calls, so treat it like a password. serve keeps it in portcullis.dashboard
next to the config file while it runs.`,
		Example: `  portcullis dashboard --open`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDashboard(cmd, opts)
		},
	}
	cmd.Flags().StringVarP(&opts.configPath, "config", "c", "portcullis.yaml", "config file")
	cmd.Flags().BoolVar(&opts.open, "open", false, "open it in the default browser")
	return cmd
}

func runDashboard(cmd *cobra.Command, opts dashboardOptions) error {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	if !cfg.Dashboard.Enabled {
		return fmt.Errorf("%s doesn't turn the dashboard on (dashboard: {enabled: true})", opts.configPath)
	}
	b, err := os.ReadFile(cfg.DashboardURLPath())
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no dashboard is running: start portcullis serve first")
	}
	if err != nil {
		return err
	}
	u := strings.TrimSpace(string(b))
	// Only ever open a page on this machine, whatever the file says.
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "http" || !isLoopback(u) {
		return fmt.Errorf("%s doesn't hold a local dashboard URL", cfg.DashboardURLPath())
	}
	if !opts.open {
		fmt.Fprintln(cmd.OutOrStdout(), u)
		return nil
	}
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	return exec.CommandContext(cmd.Context(), opener, u).Run()
}
