// Package audit records every message portcullis handles in a SQLite
// database, so a session can be searched and replayed later.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// Directions, as stored in Event.Direction.
const (
	ClientToServer = "client->server"
	ServerToClient = "server->client"
	Internal       = "portcullis" // something portcullis noticed, such as an upstream exiting
)

// Event is one message, or one request together with its response.
type Event struct {
	ID        int64
	SessionID string
	Time      time.Time // when the message arrived
	Direction string
	Upstream  string // the server it was routed to; "" for portcullis itself
	Method    string
	Tool      string // the tool's name as the client sees it (fs__read_file)
	Params    string // JSON, possibly truncated
	Result    string // JSON, possibly truncated
	Error     string // a protocol error; tool failures are in Result with IsError
	IsError   bool   // the call failed, as a protocol error or a tool error
	Duration  time.Duration

	// The policy's decision on a tool call; empty if there's no policy.
	Decision string // allow, deny, require_approval or rate_limit
	Rule     string // the rule that decided; "" for the policy's default
	Reason   string
	// What log_only rules would have decided, if that differs.
	WouldDecision string
	WouldRule     string

	// Findings is what portcullis noticed in the message, such as
	// "redacted: github_token" or a tool definition's scan findings.
	Findings string
}

// DecisionHeld is the decision recorded for a call to a tool that is held
// back because its definition changed, wasn't approved, or looks poisoned.
const DecisionHeld = "held"

// isBlocked is true for events whose call the policy stopped.
const isBlocked = `decision IN ('deny', 'require_approval', 'rate_limit', 'held')`

// Session is one client connection.
type Session struct {
	ID            string
	Started       time.Time
	Ended         time.Time // zero while the session is open
	Client        string    // client name and version, if it sent them
	Version       string    // portcullis version
	Upstreams     string    // comma-separated server names
	Events        int
	FailedEvents  int
	ToolCallCount int
	BlockedCalls  int
}

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	started_ns INTEGER NOT NULL,
	ended_ns   INTEGER,
	client     TEXT NOT NULL DEFAULT '',
	version    TEXT NOT NULL DEFAULT '',
	upstreams  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY,
	session_id  TEXT NOT NULL REFERENCES sessions(id),
	time_ns     INTEGER NOT NULL,
	direction   TEXT NOT NULL,
	upstream    TEXT NOT NULL DEFAULT '',
	method      TEXT NOT NULL,
	tool        TEXT NOT NULL DEFAULT '',
	params      TEXT NOT NULL DEFAULT '',
	result      TEXT NOT NULL DEFAULT '',
	error       TEXT NOT NULL DEFAULT '',
	is_error    INTEGER NOT NULL DEFAULT 0,
	duration_ns INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, time_ns);
CREATE INDEX IF NOT EXISTS events_tool ON events(tool);
`

// migrations bring a database from schema version i to i+1. Version 0 is
// the schema above, from before the policy engine.
var migrations = []string{
	`ALTER TABLE events ADD COLUMN decision TEXT NOT NULL DEFAULT '';
	 ALTER TABLE events ADD COLUMN rule TEXT NOT NULL DEFAULT '';
	 ALTER TABLE events ADD COLUMN reason TEXT NOT NULL DEFAULT '';
	 ALTER TABLE events ADD COLUMN would_decision TEXT NOT NULL DEFAULT '';
	 ALTER TABLE events ADD COLUMN would_rule TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE events ADD COLUMN findings TEXT NOT NULL DEFAULT '';`,
}

// Store is an open audit database. It is safe for concurrent use.
type Store struct {
	db         *sql.DB
	maxPayload int
}

// Open opens or creates the database at path. Params and results longer
// than maxPayload bytes are truncated; maxPayload <= 0 stores them in full.
func Open(path string, maxPayload int) (*Store, error) {
	// Create the file ourselves so it's private from the start: it holds tool
	// arguments and results. SQLite gives its -wal and -shm files the same mode.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	_ = f.Close()

	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	// One connection: SQLite allows one writer at a time anyway, and this
	// keeps writes from separate goroutines from contending for the lock.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: setting up %s: %w", path, err)
	}
	return &Store{db: db, maxPayload: maxPayload}, nil
}

// migrate creates the schema or brings an older database up to date. The
// schema version is kept in SQLite's user_version.
func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("the database is from a newer portcullis (schema version %d; this one knows %d)", version, len(migrations))
	}
	if version == len(migrations) {
		return nil
	}
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		if _, err := tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("upgrading the schema to version %d: %w", i+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// StartSession records the start of a session.
func (s *Store) StartSession(ctx context.Context, sess Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, started_ns, client, version, upstreams) VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.Started.UnixNano(), sess.Client, sess.Version, sess.Upstreams)
	return err
}

// SetClient records which client a session belongs to, once it has said so.
func (s *Store) SetClient(ctx context.Context, sessionID, client string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET client = ? WHERE id = ?`, client, sessionID)
	return err
}

// EndSession records the end of a session.
func (s *Store) EndSession(ctx context.Context, sessionID string, ended time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET ended_ns = ? WHERE id = ?`, ended.UnixNano(), sessionID)
	return err
}

// Record stores an event.
func (s *Store) Record(ctx context.Context, e Event) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (session_id, time_ns, direction, upstream, method, tool, params, result, error, is_error, duration_ns,
		                     decision, rule, reason, would_decision, would_rule, findings)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SessionID, e.Time.UnixNano(), e.Direction, e.Upstream, e.Method, e.Tool,
		s.truncate(e.Params), s.truncate(e.Result), e.Error, e.IsError, int64(e.Duration),
		e.Decision, e.Rule, e.Reason, e.WouldDecision, e.WouldRule, e.Findings)
	return err
}

// truncatedMarker ends a payload that was cut short.
const truncatedMarker = "…[truncated]"

func (s *Store) truncate(v string) string {
	if s.maxPayload <= 0 || len(v) <= s.maxPayload {
		return v
	}
	return v[:s.maxPayload] + truncatedMarker
}

// Filter selects events. Zero fields match everything.
type Filter struct {
	SessionID string
	Tool      string // exact name, or a prefix ending in "*" such as "fs__*"
	Method    string
	Upstream  string
	OnlyFails bool
	Blocked   bool // only calls the policy stopped
	Decision  string
	Rule      string
	// LogOnly selects calls a log_only rule would have decided differently.
	LogOnly bool
	// Flagged selects events with findings: redactions, flagged tools.
	Flagged bool
	Since   time.Time
	Limit   int // 0 means no limit
}

// Events returns the matching events, oldest first.
func (s *Store) Events(ctx context.Context, f Filter) ([]Event, error) {
	var where []string
	var args []any
	add := func(cond string, arg any) {
		where = append(where, cond)
		args = append(args, arg)
	}
	if f.SessionID != "" {
		add("session_id = ?", f.SessionID)
	}
	if prefix, ok := strings.CutSuffix(f.Tool, "*"); ok {
		add("substr(tool, 1, ?) = ?", len(prefix))
		args = append(args, prefix)
	} else if f.Tool != "" {
		add("tool = ?", f.Tool)
	}
	if f.Method != "" {
		add("method = ?", f.Method)
	}
	if f.Upstream != "" {
		add("upstream = ?", f.Upstream)
	}
	if f.OnlyFails {
		where = append(where, "is_error = 1")
	}
	if f.Blocked {
		where = append(where, isBlocked)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.Rule != "" {
		add("(rule = ? OR would_rule = ?)", f.Rule)
		args = append(args, f.Rule)
	}
	if f.LogOnly {
		where = append(where, "would_decision != ''")
	}
	if f.Flagged {
		where = append(where, "findings != ''")
	}
	if !f.Since.IsZero() {
		add("time_ns >= ?", f.Since.UnixNano())
	}

	q := `SELECT id, session_id, time_ns, direction, upstream, method, tool, params, result, error, is_error, duration_ns,
	             decision, rule, reason, would_decision, would_rule, findings FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// The newest Limit events, returned oldest first. An event is stored
	// when its response is ready, so order by arrival time rather than id.
	q += " ORDER BY time_ns DESC, id DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	q = "SELECT * FROM (" + q + ") ORDER BY time_ns, id"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var t, d int64
		if err := rows.Scan(&e.ID, &e.SessionID, &t, &e.Direction, &e.Upstream, &e.Method, &e.Tool,
			&e.Params, &e.Result, &e.Error, &e.IsError, &d,
			&e.Decision, &e.Rule, &e.Reason, &e.WouldDecision, &e.WouldRule, &e.Findings); err != nil {
			return nil, err
		}
		e.Time, e.Duration = time.Unix(0, t), time.Duration(d)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Sessions returns the most recent sessions, newest first, with event counts.
func (s *Store) Sessions(ctx context.Context, limit int) ([]Session, error) {
	q := `
	SELECT s.id, s.started_ns, COALESCE(s.ended_ns, 0), s.client, s.version, s.upstreams,
	       COUNT(e.id), COALESCE(SUM(e.is_error), 0), COALESCE(SUM(e.method = 'tools/call'), 0),
	       COALESCE(SUM(e.` + isBlocked + `), 0)
	FROM sessions s LEFT JOIN events e ON e.session_id = s.id
	GROUP BY s.id ORDER BY s.started_ns DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		var started, ended int64
		if err := rows.Scan(&sess.ID, &started, &ended, &sess.Client, &sess.Version, &sess.Upstreams,
			&sess.Events, &sess.FailedEvents, &sess.ToolCallCount, &sess.BlockedCalls); err != nil {
			return nil, err
		}
		sess.Started = time.Unix(0, started)
		if ended != 0 {
			sess.Ended = time.Unix(0, ended)
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ErrNoSessions means the database has no sessions yet.
var ErrNoSessions = errors.New("audit: no sessions recorded")

// LatestSession returns the ID of the most recent session.
func (s *Store) LatestSession(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM sessions ORDER BY started_ns DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoSessions
	}
	return id, err
}
