package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/pin"
)

// maxShownArgs is the most argument text shown for a waiting call. A call
// with more can only be denied.
const maxShownArgs = 32 << 10

// maxShownPayload caps each params or result shown in the activity list.
const maxShownPayload = 4 << 10

// shownEvents is how many recent events the activity list shows.
const shownEvents = 50

type pageView struct {
	Version   string
	SessionID string
	Approvals bool // approvals are on
	Pending   []pendingView
	Held      []heldView
	Events    []eventView
}

type pendingView struct {
	ID, Tool, Server, Rule, Reason string
	Args                           string
	TooLong                        bool
	Size                           int
	Since, Expires                 string
}

type heldView struct {
	Name, Reason string
	Status       string     // changed or new, if pinning holds it
	Hash         string     // of the pending definition, if it can be approved here
	Diff         []diffLine // from the approved definition to the pending one
}

type diffLine struct {
	Class, Text string
}

type eventView struct {
	ID                               string
	Time, Dir, Method, Tool, Server  string
	Decision, Rule, Reason, Findings string
	Error                            string
	Failed                           bool
	Params, Result                   string
	Duration                         string
}

func (s *Server) view() pageView {
	v := pageView{Version: s.o.Version, SessionID: s.o.SessionID, Approvals: s.o.Approvals != nil}
	if s.o.Approvals != nil {
		for _, r := range s.o.Approvals.Pending() {
			args := prettyJSON(r.Args)
			p := pendingView{
				ID: r.ID, Tool: r.Tool, Server: r.Server, Rule: r.Rule, Reason: r.Reason,
				Size: len(r.Args), TooLong: len(r.Args) > maxShownArgs,
				Since: r.Time.Format(time.TimeOnly), Expires: r.Expires.Format(time.TimeOnly),
			}
			if p.TooLong {
				args = shorten(args, maxShownArgs)
			}
			p.Args = args
			v.Pending = append(v.Pending, p)
		}
	}
	v.Held = s.heldView()
	if s.o.Feed != nil {
		for i, e := range s.o.Feed.Events() {
			if i == shownEvents {
				break
			}
			v.Events = append(v.Events, eventFrom(e))
		}
	}
	return v
}

func (s *Server) heldView() []heldView {
	held := s.o.Held()
	var entries map[string]*pin.Entry
	if s.o.Pins != nil {
		var err error
		if entries, err = s.o.Pins.Entries(); err != nil {
			s.log.Error("dashboard: reading pins", "err", err)
		}
	}
	var out []heldView
	for _, name := range slices.Sorted(maps.Keys(held)) {
		h := heldView{Name: name, Reason: held[name]}
		if e := entries[name]; e != nil && e.Pending != nil {
			var before []string
			h.Status = "new"
			if e.Definition != nil {
				before = e.Definition.Lines()
				h.Status = "changed"
			}
			h.Hash = e.Pending.Hash
			for _, line := range pin.Trim(pin.Diff(before, e.Pending.Definition.Lines()), 3) {
				h.Diff = append(h.Diff, diffLine{Class: diffClass(line), Text: line})
			}
		}
		out = append(out, h)
	}
	return out
}

func diffClass(line string) string {
	switch {
	case strings.HasPrefix(line, "+"):
		return "add"
	case strings.HasPrefix(line, "-"):
		return "del"
	}
	return ""
}

func eventFrom(e audit.Event) eventView {
	v := eventView{
		ID:   fmt.Sprintf("event-%d", e.ID),
		Time: e.Time.Format("15:04:05.000"), Dir: e.Direction, Method: e.Method, Tool: e.Tool, Server: e.Upstream,
		Decision: e.Decision, Rule: e.Rule, Reason: e.Reason, Findings: e.Findings, Error: e.Error, Failed: e.IsError,
		Params: shorten(e.Params, maxShownPayload), Result: shorten(e.Result, maxShownPayload),
	}
	if e.Duration > 0 {
		v.Duration = e.Duration.Round(time.Millisecond).String()
	}
	return v
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// prettyJSON indents JSON for reading. The text is otherwise unchanged:
// strings keep every character, so visible can show the hidden ones.
func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// visible escapes s for HTML and shows characters that hide or disguise
// text as their code points: control characters, zero-width and bidi
// controls, tag characters and other invisible formatting. A file name like
// "invoice" + U+202E + "fdp.exe" then reads as what it is, not as the
// "invoiceexe.pdf" it would render as.
func visible(s string) template.HTML {
	var b strings.Builder
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !hidden(r) {
			i += size
			continue
		}
		b.WriteString(html.EscapeString(s[start:i]))
		fmt.Fprintf(&b, `<span class="esc" title="hidden character">U+%04X</span>`, r)
		i += size
		start = i
	}
	b.WriteString(html.EscapeString(s[start:]))
	// Safe: every part of s was escaped above.
	return template.HTML(b.String())
}

// hidden reports whether r is invisible or changes how text around it is
// shown. Newlines and tabs are kept as layout.
func hidden(r rune) bool {
	switch {
	case r == '\n', r == '\t':
		return false
	case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
		// C0 and C1 controls; format characters, which include zero-width
		// spaces and joiners, bidi controls and tag characters.
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true // variation selectors
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true // Hangul fillers, which render as blank space
	case r == 0xFFFD:
		return true // a replacement character: the text wasn't valid UTF-8
	}
	return false
}
