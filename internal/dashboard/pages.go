package dashboard

import (
	"context"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
	"github.com/blashkar/portcullis/internal/policy"
)

// The dashboard's pages, by their path under the token.
const (
	pageLive     = ""
	pageSecurity = "security"
	pageServers  = "servers"
	pageSessions = "sessions"
)

// AuditLog is the audit database, read for past sessions.
type AuditLog interface {
	Sessions(ctx context.Context, limit int) ([]audit.Session, error)
	Events(ctx context.Context, f audit.Filter) ([]audit.Event, error)
}

const (
	// shownSessions is how many past sessions are listed.
	shownSessions = 50
	// shownSessionEvents caps the events read for one past session.
	shownSessionEvents = 2000
)

type tabView struct {
	Label, Href string
	On          bool
	Count       int
	Tone        string
}

// cardView is one security event.
type cardView struct {
	Href, Time    string
	Title         string
	Verdict, Tone string
	Explain       string
	By, Outcome   string
	Summary       string
	Findings      []string
}

type serverView struct {
	Name      string
	Connected bool
	Command   string
	Sandboxed bool
	Offered   int
	Held      int
	Tools     []toolView
}

type toolView struct {
	Name, Status, Tone, Note string
	Rules                    []string
}

type sessionView struct {
	ID, Href                string
	Started, Length, Client string
	Servers                 string
	Calls, Blocked, Failed  int
	Open, Current, Selected bool
}

// tabs builds the tab bar.
func (s *Server) tabs(v *pageView, caught int) []tabView {
	held := 0
	for _, sv := range v.Servers {
		held += sv.Held
	}
	if v.Servers == nil {
		held = len(s.o.Held())
	}
	return []tabView{
		{Label: "Live", Href: "./", On: v.Page == pageLive, Count: len(v.Pending), Tone: toneInfo},
		{Label: "Security events", Href: pageSecurity, On: v.Page == pageSecurity, Count: caught, Tone: toneBad},
		{Label: "Servers & tools", Href: pageServers, On: v.Page == pageServers, Count: held, Tone: toneBad},
		{Label: "Sessions", Href: pageSessions, On: v.Page == pageSessions},
	}
}

// caughtEvents counts the events portcullis acted on, among those kept.
func caughtEvents(events []Event) int {
	n := 0
	for _, e := range events {
		if tell(e).caught {
			n++
		}
	}
	return n
}

func (s *Server) securityView(v *pageView, events []Event) {
	for _, e := range events {
		st := tell(e)
		if !st.caught {
			continue
		}
		c := cardView{
			Href: nav{base: "./"}.link(showAll, e.ID), Time: e.Time.Format(time.TimeOnly),
			Title: st.title, Verdict: st.verdict, Tone: st.tone, Explain: st.explain,
			By: st.by, Outcome: st.outcome, Summary: e.Summary,
		}
		if e.Findings != "" {
			c.Findings = strings.Split(e.Findings, "; ")
		}
		v.Cards = append(v.Cards, c)
	}
}

func (s *Server) serversView(v *pageView) {
	if s.o.Servers == nil {
		return
	}
	v.Servers = []serverView{}
	for _, info := range s.o.Servers() {
		cmd := s.o.Commands[info.Name]
		sv := serverView{
			Name: info.Name, Connected: info.Connected, Offered: len(info.Tools), Held: len(info.Held),
			Command: shorten(strings.Join(cmd, " "), 300), Sandboxed: sandboxed(cmd),
		}
		for _, t := range info.Tools {
			sv.Tools = append(sv.Tools, s.toolView(t))
		}
		for _, name := range sortedKeys(info.Held) {
			sv.Tools = append(sv.Tools, toolView{Name: name, Status: "held back", Tone: toneBad, Note: info.Held[name]})
		}
		v.Servers = append(v.Servers, sv)
	}
}

// sandboxed reports whether a server's command starts it in portcullis's
// Docker sandbox.
func sandboxed(cmd []string) bool {
	if len(cmd) == 0 {
		return false
	}
	p := filepath.ToSlash(cmd[0])
	return filepath.Base(p) == "run.sh" && filepath.Base(filepath.Dir(p)) == "sandbox"
}

// toolView says what the policy does with calls to an offered tool.
func (s *Server) toolView(tool string) toolView {
	t := toolView{Name: tool, Status: "allowed", Tone: toneOK}
	rules, def := s.o.Policy.RulesFor(tool)
	decided := false
	maybe := ""
	for _, r := range rules {
		desc := r.Name + ": "
		switch {
		case r.RateLimit != "":
			desc += "at most " + r.RateLimit
		case r.Conditional:
			desc += actionText(r.Action) + " for some arguments"
		default:
			desc += actionText(r.Action)
		}
		if r.LogOnly {
			desc += " (log only)"
		}
		t.Rules = append(t.Rules, desc)
		if decided || r.LogOnly || r.Action == "" {
			continue
		}
		if r.Conditional {
			if r.Action != policy.Allow && maybe == "" {
				maybe = actionText(r.Action)
			}
			continue
		}
		decided = true
		t.Status, t.Tone = statusOf(r.Action)
	}
	if !decided {
		t.Status, t.Tone = statusOf(def)
		if s.o.Policy != nil {
			t.Rules = append(t.Rules, "otherwise the default: "+actionText(def))
		}
	}
	if maybe != "" && t.Tone == toneOK {
		t.Status, t.Tone = "depends on arguments", toneWarn
		t.Note = "Some calls are " + maybe + ", depending on their arguments."
	}
	return t
}

func actionText(a policy.Action) string {
	switch a {
	case policy.Deny:
		return "denied"
	case policy.RequireApproval:
		return "needs approval"
	}
	return "allowed"
}

func statusOf(a policy.Action) (status, tone string) {
	switch a {
	case policy.Deny:
		return "denied", toneBad
	case policy.RequireApproval:
		return "needs approval", toneInfo
	}
	return "allowed", toneOK
}

// sessionID matches the IDs portcullis gives sessions; anything else in the
// query is ignored.
var sessionID = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

func (s *Server) sessionsView(r *http.Request, v *pageView) {
	if s.o.Audit == nil {
		return
	}
	v.HasAudit = true
	q := r.URL.Query()
	id := q.Get("id")
	if !sessionID.MatchString(id) {
		id = ""
	}
	sessions, err := s.o.Audit.Sessions(r.Context(), shownSessions)
	if err != nil {
		s.log.Error("dashboard: reading sessions", "err", err)
		v.AuditErr = true
		return
	}
	for _, se := range sessions {
		sv := sessionView{
			ID: se.ID, Href: pageSessions + "?id=" + se.ID, Started: se.Started.Format("2006-01-02 15:04"),
			Client: se.Client, Servers: strings.ReplaceAll(se.Upstreams, ",", ", "),
			Calls: se.ToolCallCount, Blocked: se.BlockedCalls, Failed: se.FailedEvents,
			Open: se.Ended.IsZero(), Current: se.ID == s.o.SessionID, Selected: se.ID == id,
		}
		if !sv.Open {
			sv.Length = se.Ended.Sub(se.Started).Round(time.Second).String()
		}
		v.Sessions = append(v.Sessions, sv)
		if sv.Selected {
			v.Picked = &v.Sessions[len(v.Sessions)-1]
		}
	}
	if id == "" {
		return
	}
	if v.Picked == nil {
		v.Gone = true
		return
	}
	raw, err := s.o.Audit.Events(r.Context(), audit.Filter{SessionID: id})
	if err != nil {
		s.log.Error("dashboard: reading a session", "err", err)
		v.AuditErr = true
		return
	}
	// Newest first, only what the timeline shows, and at most a bounded
	// number, read from the newest end.
	var events []Event
	for i := len(raw) - 1; i >= 0 && len(events) < shownSessionEvents; i-- {
		e := raw[i]
		if !shown(e) {
			continue
		}
		ev := readable(s.o.Redactor, e)
		ev.Details = detailsFromAudit(e)
		if ev.ID == 0 {
			ev.ID = int64(i + 1)
		}
		events = append(events, ev)
	}
	n := nav{base: pageSessions, session: id, show: parseShow(q.Get("show")), event: parseEvent(q.Get("event"))}
	v.Show = n.show
	v.Unselect = n.link(n.show, 0)
	var found bool
	v.Rows, v.Detail, found = timeline(events, n)
	if n.event > 0 && !found {
		v.Gone = true
	}
	v.Filters = filters(n)
}

// detailsFromAudit recovers what the gateway did to a message from what the
// audit log keeps as text. Redaction counts are per kind, at least one.
func detailsFromAudit(e audit.Event) gateway.Details {
	var d gateway.Details
	for _, f := range strings.Split(e.Findings, "; ") {
		switch {
		case strings.HasPrefix(f, "redacted: "):
			d.Redacted = map[string]int{}
			for _, kind := range strings.Split(strings.TrimPrefix(f, "redacted: "), ", ") {
				name, times, _ := strings.Cut(kind, "×")
				n, err := strconv.Atoi(times)
				if err != nil || n < 1 {
					n = 1
				}
				d.Redacted[name] += n
			}
		case strings.HasPrefix(f, "prompt injection ("):
			d.Injection = true
		case f != "" && (e.Method == "tools/call" || e.Method == "resources/read" || e.Method == "prompts/get"):
			d.Suspicious = true
		}
	}
	if d.Injection {
		d.Suspicious = false
		d.Withheld = strings.Contains(e.Result, "withheld because it appears to contain a prompt injection") ||
			strings.Contains(e.Error, "withheld because it appears to contain a prompt injection")
	}
	switch e.Reason {
	case "approved in the dashboard":
		d.Approval = "approved"
	case "denied in the dashboard":
		d.Approval = "denied"
	case "nobody answered in time":
		d.Approval = "expired"
	case "the client cancelled the call while it waited":
		d.Approval = "cancelled"
	case "too many calls were already waiting for approval":
		d.Approval = "refused"
	}
	return d
}

// filters builds the timeline's filter links.
func filters(n nav) []filterView {
	var out []filterView
	for _, f := range []struct{ show, label string }{
		{showAll, "All"}, {showCaught, "Caught by portcullis"}, {showThrough, "Went through"},
	} {
		out = append(out, filterView{Label: f.label, Href: n.link(f.show, n.event), On: f.show == n.show})
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// pageTitle names a page in the browser's tab.
func pageTitle(page string) string {
	switch page {
	case pageSecurity:
		return "Security events"
	case pageServers:
		return "Servers & tools"
	case pageSessions:
		return "Sessions"
	}
	return "Live"
}
