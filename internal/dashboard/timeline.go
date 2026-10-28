package dashboard

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blashkar/portcullis/internal/audit"
)

// Tones color stages and verdicts: ok went through, bad was stopped, warn
// went through changed or flagged, info needed a person, mute is neutral.
const (
	toneOK   = "ok"
	toneBad  = "bad"
	toneWarn = "warn"
	toneInfo = "info"
	toneMute = "mute"
)

// Timeline filters.
const (
	showAll     = "all"
	showCaught  = "caught"
	showThrough = "through"
)

// stage is one step of a call's way through portcullis, such as
// "policy denied".
type stage struct {
	Who, What, Tone string
}

// rowView is one line of the timeline.
type rowView struct {
	ID       int64
	Href     string
	Selected bool
	Caught   bool
	Time     string
	Title    string // the tool, or the method and what it's about
	Summary  string
	Stages   []stage
}

// detailView is the selected event, in full.
type detailView struct {
	Title, Time, Server string
	Verdict, Tone       string
	Explain             string
	Rule, Reason, Took  string
	InputLabel, Input   string
	OutputLabel, Output string
	Findings            []string
	Would               string // what a log_only rule would have done
	Failed, HasRule     bool
}

// story is what the dashboard says about one event.
type story struct {
	title   string
	stages  []stage
	verdict string
	tone    string
	explain string
	caught  bool // portcullis acted on it: blocked, held, redacted or flagged
}

// tell works out the story of e.
func tell(e Event) story {
	switch e.Method {
	case "tools/call", "prompts/get", "resources/read":
		return tellCall(e)
	case "tool/changed":
		return story{
			title: e.Tool,
			stages: []stage{
				{"server", "changed the tool", toneWarn},
				{"portcullis", "held it", toneBad},
				{"agent", "not offered", toneMute},
			},
			verdict: "Rug pull held", tone: toneBad, caught: true,
			explain: "The server changed this tool after it was approved. It is held back until you review the change.",
		}
	case "tool/held":
		return story{
			title: e.Tool,
			stages: []stage{
				{"server", "offered it", toneMute},
				{"portcullis", "held it back", toneBad},
				{"agent", "not offered", toneMute},
			},
			verdict: "Tool held back", tone: toneBad, caught: true,
			explain: "The agent isn't offered this tool. " + sentence(e.Reason),
		}
	case "tool/flagged":
		return story{
			title: e.Tool,
			stages: []stage{
				{"server", "offered it", toneMute},
				{"portcullis", "flagged it", toneWarn},
				{"agent", "offered", toneOK},
			},
			verdict: "Tool flagged", tone: toneWarn, caught: true,
			explain: "The scanner noticed something in this tool's definition, not enough to hide it.",
		}
	case "upstream/disconnected":
		return story{
			title: e.Upstream,
			stages: []stage{
				{"server", "disconnected", toneBad},
				{"portcullis", "removed its tools", toneMute},
			},
			verdict: "Server disconnected", tone: toneBad,
			explain: "The server stopped answering. Its tools are no longer offered.",
		}
	}
	return story{title: e.Method, verdict: e.Method, tone: toneMute}
}

func tellCall(e Event) story {
	s := story{title: e.Tool, verdict: "Allowed", tone: toneOK}
	verb := "called"
	switch e.Method {
	case "prompts/get":
		s.title, verb, s.verdict = "prompt", "asked for a prompt", "Answered"
	case "resources/read":
		s.title, verb, s.verdict = "resource", "read a resource", "Answered"
	}
	s.stages = append(s.stages, stage{"agent", verb, toneMute})
	ruled := ""
	if e.Rule != "" {
		ruled = fmt.Sprintf(" Rule %q decided it.", e.Rule)
	}

	forwarded := false
	switch e.Decision {
	case audit.DecisionHeld:
		s.stages = append(s.stages, stage{"portcullis", "tool held", toneBad})
		s.verdict, s.tone, s.caught = "Blocked: tool held", toneBad, true
		s.explain = "The tool is held back, so the call never reached the server. " + sentence(e.Reason)
	case "deny":
		s.stages = append(s.stages, stage{"policy", "denied", toneBad})
		s.verdict, s.tone, s.caught = "Denied by policy", toneBad, true
		s.explain = "The policy blocked the call before it reached the server." + ruled + reasonSentence(e.Reason)
	case "rate_limit":
		s.stages = append(s.stages, stage{"policy", "rate limited", toneBad})
		s.verdict, s.tone, s.caught = "Rate limited", toneBad, true
		s.explain = "Too many calls in a short time, so this one was blocked." + ruled
	case audit.DecisionApproved:
		s.stages = append(s.stages, stage{"policy", "needs approval", toneInfo}, stage{"you", "approved", toneInfo})
		s.verdict, s.tone = "Approved by you", toneInfo
		s.explain = "This call waited for a person, and was approved." + ruled
		forwarded = true
	case "require_approval":
		s.stages = append(s.stages, stage{"policy", "needs approval", toneInfo})
		s.tone, s.caught = toneBad, true
		switch e.Details.Approval {
		case "denied":
			s.stages = append(s.stages, stage{"you", "denied", toneBad})
			s.verdict = "Denied by you"
		case "expired":
			s.stages = append(s.stages, stage{"you", "didn't answer", toneBad})
			s.verdict = "Not approved in time"
		case "cancelled":
			s.stages = append(s.stages, stage{"agent", "gave up waiting", toneMute})
			s.verdict, s.tone = "Cancelled while waiting", toneMute
		default:
			s.stages = append(s.stages, stage{"portcullis", "couldn't ask", toneBad})
			s.verdict = "Not approved"
		}
		s.explain = "This call needed a person's approval and didn't get it, so it never reached the server. " + sentence(e.Reason)
	case "allow":
		s.stages = append(s.stages, stage{"policy", "allowed", toneOK})
		forwarded = true
		s.explain = "Nothing in the policy blocked it." + ruled
	default:
		forwarded = true
	}

	if !forwarded {
		s.stages = append(s.stages, stage{"server", "not reached", toneMute}, stage{"agent", "got an error", toneWarn})
		return s
	}
	if e.Error != "" {
		s.stages = append(s.stages, stage{"server", "failed", toneWarn}, stage{"agent", "got an error", toneWarn})
		s.verdict, s.tone = "Failed", toneWarn
		s.explain = "The call went through, but it failed: " + sentence(e.Error)
		return s
	}
	answer := stage{"server", "answered", toneMute}
	if e.IsError && !e.Details.Withheld {
		answer = stage{"server", "returned an error", toneWarn}
	}
	s.stages = append(s.stages, answer)

	d := e.Details
	n := 0
	for _, c := range d.Redacted {
		n += c
	}
	got := stage{"agent", "got the result", toneOK}
	switch {
	case d.Withheld:
		s.stages = append(s.stages, stage{"checks", "injection", toneBad})
		got = stage{"agent", "got a notice instead", toneWarn}
		s.verdict, s.tone, s.caught = "Injection withheld", toneBad, true
		s.explain = "The result looked like a prompt injection, so the agent got a notice instead of it."
	case d.Injection:
		s.stages = append(s.stages, stage{"checks", "injection", toneWarn})
		got = stage{"agent", "got it unchanged", toneWarn}
		s.explain = "The result looked like a prompt injection. It was only logged."
		if strings.HasPrefix(e.Output, "[portcullis] Warning") {
			got = stage{"agent", "got it with a warning", toneWarn}
			s.explain = "The result looked like a prompt injection, so it went to the agent with a warning in front."
		}
		s.verdict, s.tone, s.caught = "Prompt injection flagged", toneWarn, true
	case d.Suspicious:
		s.stages = append(s.stages, stage{"checks", "suspicious, judged safe", toneMute})
	case n == 0:
		s.stages = append(s.stages, stage{"checks", "clean", toneOK})
	}
	if n > 0 {
		s.stages = append(s.stages, stage{"checks", plural(n, "secret") + " redacted", toneWarn})
		if !s.caught {
			s.verdict, s.tone, s.caught = "Secrets redacted", toneWarn, true
			s.explain = fmt.Sprintf("The result held %s. They were replaced before the agent or the audit log saw them.", plural(n, "secret"))
		}
		if got.Tone == toneOK {
			got.What = "got it redacted"
		}
	}
	if e.IsError && !d.Withheld {
		got = stage{"agent", "got the error", toneWarn}
	}
	s.stages = append(s.stages, got)
	return s
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// sentence makes s a sentence: capitalized, with a full stop.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[n:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func reasonSentence(r string) string {
	if r == "" {
		return ""
	}
	return " " + sentence(r)
}

// timeline builds the rows to show, newest first, and the selected event.
func timeline(events []Event, show string, selected int64) (rows []rowView, detail *detailView, found bool) {
	for _, e := range events {
		s := tell(e)
		if e.ID == selected {
			found = true
			detail = detailOf(e, s)
		}
		if show == showCaught && !s.caught || show == showThrough && s.caught {
			continue
		}
		title := s.title
		if e.Method == "resources/read" || e.Method == "prompts/get" {
			title = e.Method
		}
		rows = append(rows, rowView{
			ID: e.ID, Href: link(show, e.ID), Selected: e.ID == selected, Caught: s.caught,
			Time: e.Time.Format(time.TimeOnly), Title: title, Summary: e.Summary, Stages: s.stages,
		})
	}
	return rows, detail, found
}

func detailOf(e Event, s story) *detailView {
	d := &detailView{
		Title: s.title, Time: e.Time.Format("15:04:05.000"), Server: e.Upstream,
		Verdict: s.verdict, Tone: s.tone, Explain: s.explain,
		Rule: e.Rule, HasRule: e.Decision != "", Reason: e.Reason, Failed: e.IsError,
		Input: e.Input, Output: e.Output,
		InputLabel: "What the agent sent", OutputLabel: "What the agent got back",
	}
	if d.Rule == "" && d.HasRule {
		d.Rule = "(the policy's default)"
	}
	if e.Duration > 0 {
		d.Took = e.Duration.Round(time.Millisecond).String()
		if e.Duration < time.Millisecond {
			d.Took = "under 1ms"
		}
	}
	switch e.Method {
	case "tool/changed", "tool/held", "tool/flagged":
		d.InputLabel = "The definition the server sent"
	case "upstream/disconnected":
		d.Explain += " " + sentence(e.Error)
	}
	if e.WouldDecision != "" {
		d.Would = e.WouldDecision
		if e.WouldRule != "" {
			d.Would += fmt.Sprintf(" (rule %q, log only)", e.WouldRule)
		}
	}
	if e.Findings != "" {
		d.Findings = strings.Split(e.Findings, "; ")
	}
	return d
}

// link is the dashboard's address with a filter and a selected event.
func link(show string, event int64) string {
	q := url.Values{}
	if show != showAll {
		q.Set("show", show)
	}
	if event > 0 {
		q.Set("event", strconv.FormatInt(event, 10))
	}
	if len(q) == 0 {
		return "./"
	}
	return "./?" + q.Encode()
}

// parseShow reads the filter from a request's query; anything else is all.
func parseShow(s string) string {
	switch s {
	case showCaught, showThrough:
		return s
	}
	return showAll
}

// parseEvent reads the selected event from a request's query; 0 if none.
func parseEvent(s string) int64 {
	if len(s) > 18 {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
