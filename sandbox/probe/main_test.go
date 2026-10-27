package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Each check must fail when the sandbox doesn't hold, or a broken probe
// would pass everything.

func TestConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if run([]string{"connect", "127.0.0.1", port}) == nil {
		t.Error("a connection that succeeded passed")
	}
	_ = ln.Close()
	if err := run([]string{"connect", "127.0.0.1", port}); err != nil {
		t.Errorf("a refused connection failed: %v", err)
	}
}

func TestStatus(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		statusFile = filepath.Join(dir, "status")
		if err := os.WriteFile(statusFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { statusFile = "/proc/self/status" })

	write("Name:\tprobe\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n")
	if err := run([]string{"caps"}); err != nil {
		t.Errorf("caps: %v", err)
	}
	if err := run([]string{"nonewprivs"}); err != nil {
		t.Errorf("nonewprivs: %v", err)
	}
	write("CapEff:\t00000000a80425fb\nNoNewPrivs:\t0\n")
	if run([]string{"caps"}) == nil || run([]string{"nonewprivs"}) == nil {
		t.Error("capabilities or privilege escalation passed")
	}
	write("Name:\tprobe\n")
	if run([]string{"caps"}) == nil {
		t.Error("a missing field passed")
	}
}

func TestAbsentAndTouch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sock")
	if err := run([]string{"absent", p}); err != nil {
		t.Errorf("absent: %v", err)
	}
	if err := run([]string{"touch", p}); err != nil {
		t.Errorf("touch: %v", err)
	}
	if run([]string{"absent", p}) == nil {
		t.Error("a file that exists passed as absent")
	}
	if run([]string{"touch", filepath.Join(dir, "no", "such", "dir")}) == nil {
		t.Error("touch in a missing directory passed")
	}
}

func TestInterfaces(t *testing.T) {
	lo := net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback}
	if err := upButLoopback([]net.Interface{lo, {Name: "eth0"}}); err != nil {
		t.Errorf("loopback and a down interface: %v", err)
	}
	if upButLoopback([]net.Interface{lo, {Name: "eth0", Flags: net.FlagUp}}) == nil {
		t.Error("an interface that's up passed")
	}
}

func TestBadArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"connect", "1.1.1.1"}, {"absent"}} {
		if run(args) == nil {
			t.Errorf("%q passed", args)
		}
	}
}
