package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T, maxPayload int) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(path, maxPayload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestRecordAndQuery(t *testing.T) {
	s, path := openTestStore(t, 0)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

	if _, err := s.LatestSession(ctx); !errors.Is(err, ErrNoSessions) {
		t.Fatalf("LatestSession on an empty db: %v", err)
	}
	for i, id := range []string{"old", "new"} {
		if err := s.StartSession(ctx, Session{ID: id, Started: t0.Add(time.Duration(i) * time.Hour), Version: "test", Upstreams: "fs,git"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetClient(ctx, "new", "claude-code 2.1"); err != nil {
		t.Fatal(err)
	}

	events := []Event{
		{SessionID: "old", Time: t0, Direction: ClientToServer, Method: "tools/list"},
		{
			SessionID: "new", Time: t0.Add(time.Hour), Direction: ClientToServer, Method: "tools/call", Upstream: "fs", Tool: "fs__read_file",
			Params: `{"name":"fs__read_file","arguments":{"path":"/w/a"}}`, Result: `{"content":[]}`, Duration: 3 * time.Millisecond,
		},
		{SessionID: "new", Time: t0.Add(time.Hour + time.Second), Direction: ClientToServer, Method: "tools/call", Upstream: "git", Tool: "git__git_log", IsError: true, Error: "repo not found"},
		{SessionID: "new", Time: t0.Add(time.Hour + 2*time.Second), Direction: ServerToClient, Method: "notifications/tools/list_changed"},
	}
	for _, e := range events {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	if id, err := s.LatestSession(ctx); err != nil || id != "new" {
		t.Errorf("LatestSession = %q, %v", id, err)
	}

	tests := []struct {
		name string
		f    Filter
		want []string // methods or tools of the matching events, in order
	}{
		{"all", Filter{}, []string{"tools/list", "fs__read_file", "git__git_log", "notifications/tools/list_changed"}},
		{"session", Filter{SessionID: "old"}, []string{"tools/list"}},
		{"tool", Filter{Tool: "fs__read_file"}, []string{"fs__read_file"}},
		{"tool prefix", Filter{Tool: "git__*"}, []string{"git__git_log"}},
		{"upstream", Filter{Upstream: "fs"}, []string{"fs__read_file"}},
		{"method", Filter{Method: "tools/call"}, []string{"fs__read_file", "git__git_log"}},
		{"failures", Filter{OnlyFails: true}, []string{"git__git_log"}},
		{"since", Filter{Since: t0.Add(time.Hour + time.Second)}, []string{"git__git_log", "notifications/tools/list_changed"}},
		{"newest two, oldest first", Filter{Limit: 2}, []string{"git__git_log", "notifications/tools/list_changed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Events(ctx, tt.f)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range got {
				if e.Tool != "" {
					names = append(names, e.Tool)
				} else {
					names = append(names, e.Method)
				}
			}
			if strings.Join(names, " ") != strings.Join(tt.want, " ") {
				t.Errorf("got %v, want %v", names, tt.want)
			}
		})
	}

	// Fields survive the round trip.
	got, _ := s.Events(ctx, Filter{Tool: "fs__read_file"})
	e := got[0]
	if e.Params != events[1].Params || e.Result != events[1].Result || e.Duration != 3*time.Millisecond || !e.Time.Equal(events[1].Time) || e.Direction != ClientToServer {
		t.Errorf("round trip: %+v", e)
	}

	sessions, err := s.Sessions(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].ID != "new" {
		t.Fatalf("sessions = %+v", sessions)
	}
	if n := sessions[0]; n.Events != 3 || n.FailedEvents != 1 || n.ToolCallCount != 2 || n.Client != "claude-code 2.1" || n.Upstreams != "fs,git" || !n.Ended.IsZero() {
		t.Errorf("newest session = %+v", n)
	}

	if err := s.EndSession(ctx, "new", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sessions, _ = s.Sessions(ctx, 1)
	if len(sessions) != 1 || !sessions[0].Ended.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("after EndSession: %+v", sessions)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("database mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestPayloadsAreTruncated(t *testing.T) {
	s, _ := openTestStore(t, 10)
	ctx := context.Background()
	if err := s.StartSession(ctx, Session{ID: "s", Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, Event{SessionID: "s", Time: time.Now(), Direction: ClientToServer, Method: "m", Params: "0123456789abcdef", Result: "short"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Events(ctx, Filter{})
	if got[0].Params != "0123456789"+truncatedMarker || got[0].Result != "short" {
		t.Errorf("params %q, result %q", got[0].Params, got[0].Result)
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	s, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartSession(ctx, Session{ID: "first", Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if id, err := s.LatestSession(ctx); err != nil || id != "first" {
		t.Errorf("after reopening: %q, %v", id, err)
	}
}

func TestConcurrentRecords(t *testing.T) {
	s, _ := openTestStore(t, 0)
	ctx := context.Background()
	if err := s.StartSession(ctx, Session{ID: "s", Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if err := s.Record(ctx, Event{SessionID: "s", Time: time.Now(), Direction: ClientToServer, Method: "ping", Params: strings.Repeat("x", i)}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	got, err := s.Events(ctx, Filter{})
	if err != nil || len(got) != 50 {
		t.Errorf("got %d events, %v", len(got), err)
	}
}

// Events are stored when their response is ready, so a slow call can be
// stored after a later, faster one. Queries order by arrival time.
func TestEventsOrderedByTime(t *testing.T) {
	s, _ := openTestStore(t, 0)
	ctx := context.Background()
	t0 := time.Now()
	if err := s.StartSession(ctx, Session{ID: "s", Started: t0}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{SessionID: "s", Time: t0.Add(2 * time.Millisecond), Direction: ClientToServer, Method: "fast"},
		{SessionID: "s", Time: t0.Add(time.Millisecond), Direction: ClientToServer, Method: "slow"},
	} {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Events(ctx, Filter{})
	if err != nil || len(got) != 2 || got[0].Method != "slow" || got[1].Method != "fast" {
		t.Errorf("got %+v, %v; want slow then fast", got, err)
	}
}
