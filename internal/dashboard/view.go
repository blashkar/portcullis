package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blashkar/portcullis/internal/pin"
)

// maxShownArgs is the most argument text shown for a waiting call. A call
// with more can only be denied.
const maxShownArgs = 32 << 10

// maxShownPayload caps each params or result shown in the activity list.
const maxShownPayload = 4 << 10

// shownEvents is how many recent events the timeline shows.
const shownEvents = 100

type pageView struct {
	Version   string
	SessionID string
	Approvals bool // approvals are on
	Pending   []pendingView
	Held      []heldView

	Live     bool // the gateway reports events; false in tests of other parts
	Tiles    []tileView
	Bar      []barPart
	BarWidth int // the bar's viewBox width
	Show     string
	Filters  []filterView
	Rows     []rowView
	Detail   *detailView
	Gone     bool   // the selected event is no longer kept
	Unselect string // the link that clears the selection
}

// tileView is one of the overview's numbers.
type tileView struct {
	Label, Value, Note, Tone string
}

// barPart is one part of the bar that splits the tool calls by decision,
// drawn in a viewBox 1000 wide.
type barPart struct {
	Label, Tone string
	N, X, W     int
}

type filterView struct {
	Label, Href string
	On          bool
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

func (s *Server) view(r *http.Request) pageView {
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
	if s.o.Feed == nil {
		return v
	}
	v.Live = true
	q := r.URL.Query()
	v.Show = parseShow(q.Get("show"))
	selected := parseEvent(q.Get("event"))
	v.Unselect = link(v.Show, 0)
	events := s.o.Feed.Events()
	if len(events) > shownEvents {
		events = events[:shownEvents]
	}
	var found bool
	v.Rows, v.Detail, found = timeline(events, v.Show, selected)
	v.Gone = selected > 0 && !found
	t := s.o.Feed.Totals()
	v.Tiles, v.Bar, v.BarWidth = overview(t, len(v.Pending), len(v.Held))
	for _, f := range []struct{ show, label string }{
		{showAll, "All"}, {showCaught, "Caught by portcullis"}, {showThrough, "Went through"},
	} {
		v.Filters = append(v.Filters, filterView{Label: f.label, Href: link(f.show, selected), On: f.show == v.Show})
	}
	return v
}

// overview builds the numbers at the top of the page.
func overview(t Totals, waiting, held int) ([]tileView, []barPart, int) {
	note := func(parts ...string) string {
		var out []string
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, ", ")
	}
	some := func(n int, what string) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf("%d %s", n, what)
	}
	blockedTone, heldTone, secretTone, injTone := toneMute, toneMute, toneMute, toneMute
	if t.Blocked() > 0 {
		blockedTone = toneBad
	}
	if held > 0 {
		heldTone = toneBad
	}
	if t.Redacted > 0 {
		secretTone = toneWarn
	}
	if t.Injections > 0 {
		injTone = toneWarn
	}
	tiles := []tileView{
		{Label: "Tool calls", Value: strconv.Itoa(t.Calls), Note: note(some(t.Allowed, "allowed")), Tone: toneMute},
		{
			Label: "Blocked", Value: strconv.Itoa(t.Blocked()), Tone: blockedTone,
			Note: note(some(t.Denied, "by policy"), some(t.RateLimited, "rate limited"), some(t.Held, "held tool"), some(t.NotApproved, "not approved")),
		},
		{Label: "Approved by you", Value: strconv.Itoa(t.Approved), Tone: toneInfo, Note: fmt.Sprintf("%d waiting now", waiting)},
		{Label: "Secrets redacted", Value: strconv.Itoa(t.Redacted), Tone: secretTone},
		{Label: "Injections flagged", Value: strconv.Itoa(t.Injections), Tone: injTone, Note: some(t.Withheld, "withheld")},
		{Label: "Tools held back", Value: strconv.Itoa(held), Tone: heldTone, Note: "right now"},
	}
	parts := []barPart{
		{Label: "allowed", Tone: toneOK, N: t.Allowed},
		{Label: "approved by you", Tone: toneInfo, N: t.Approved},
		{Label: "denied by policy", Tone: toneBad, N: t.Denied + t.RateLimited},
		{Label: "not approved", Tone: toneMute, N: t.NotApproved},
		{Label: "held tool", Tone: toneWarn, N: t.Held},
	}
	// Each part is at least a sliver wide, and a gap separates them, so
	// the viewBox is as wide as they add up to.
	const gap = 6
	var bar []barPart
	x := 0
	for _, p := range parts {
		if p.N == 0 {
			continue
		}
		if len(bar) > 0 {
			x += gap
		}
		p.X, p.W = x, max(p.N*1000/t.Calls, 8)
		x += p.W
		bar = append(bar, p)
	}
	return tiles, bar, x
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
