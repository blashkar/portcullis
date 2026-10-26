// Command probe checks the sandbox from inside a container that has no
// shell, such as the demo server's scratch image. sandbox/check.sh runs it
// with docker exec; each check exits 0 when the sandbox holds.
//
//	probe uid                  prints the user ID
//	probe caps                 no effective capabilities
//	probe nonewprivs           privilege escalation is blocked
//	probe ifaces               no network interface is up except loopback
//	probe absent PATH          PATH doesn't exist
//	probe touch PATH           PATH can be created (exits 1 if not)
//	probe connect HOST PORT    a TCP connection fails
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

// statusFile is read for caps and nonewprivs; tests replace it.
var statusFile = "/proc/self/status"

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: probe uid|caps|nonewprivs|ifaces|absent|touch|connect")
	}
	need := func(n int) error {
		if len(args) != n+1 {
			return fmt.Errorf("%s takes %d arguments", args[0], n)
		}
		return nil
	}
	switch args[0] {
	case "uid":
		fmt.Println(os.Getuid())
		return nil
	case "caps":
		return status("CapEff:", "0000000000000000")
	case "nonewprivs":
		return status("NoNewPrivs:", "1")
	case "ifaces":
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		return upButLoopback(ifaces)
	case "absent":
		if err := need(1); err != nil {
			return err
		}
		// Only "doesn't exist" counts: an error such as permission denied
		// doesn't show the path is absent.
		_, err := os.Lstat(args[1])
		switch {
		case err == nil:
			return errors.New(args[1] + " exists")
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%s may exist: %w", args[1], err)
		}
		return nil
	case "touch":
		if err := need(1); err != nil {
			return err
		}
		f, err := os.OpenFile(args[1], os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return f.Close()
	case "connect":
		if err := need(2); err != nil {
			return err
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(args[1], args[2]), 3*time.Second)
		if err == nil {
			_ = c.Close()
			return errors.New("connected to " + args[1])
		}
		return nil
	}
	return errors.New("unknown check " + args[0])
}

func upButLoopback(ifaces []net.Interface) error {
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			return errors.New("interface up: " + i.Name)
		}
	}
	return nil
}

// status checks a field of /proc/self/status.
func status(field, want string) error {
	b, err := os.ReadFile(statusFile)
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, field); ok {
			if got := strings.TrimSpace(v); got != want {
				return fmt.Errorf("%s %s", field, got)
			}
			return nil
		}
	}
	return errors.New(field + " not found")
}
