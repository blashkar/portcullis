package inject

import (
	"context"
	"fmt"
	"strings"

	"github.com/blashkar/portcullis/internal/scan"
)

// Detector combines the patterns and the guard model.
type Detector struct {
	// Guard is the guard model; nil means patterns only.
	Guard *Guard
	// GuardAll asks the guard about every text; otherwise only about text
	// a pattern found suspicious.
	GuardAll bool
}

// minGuardText is the shortest text worth asking the guard about.
const minGuardText = 20

// Verdict is the outcome of checking a text.
type Verdict struct {
	Injection bool
	Findings  []Finding
	Guard     *GuardVerdict // nil if the guard wasn't asked
	GuardErr  error         // the guard was asked and failed
}

// Check checks text. A high-severity pattern decides on its own; otherwise
// the guard, when asked, decides. If the guard fails, the patterns' verdict
// stands, and GuardErr says why.
func (d *Detector) Check(ctx context.Context, text string) Verdict {
	v := Verdict{Findings: Heuristics(text)}
	if MaxSeverity(v.Findings) == scan.High {
		v.Injection = true
		return v
	}
	if d.Guard == nil || len(strings.TrimSpace(text)) < minGuardText || (!d.GuardAll && len(v.Findings) == 0) {
		return v
	}
	g, err := d.Guard.Check(ctx, text)
	if err != nil {
		v.GuardErr = err
		return v
	}
	v.Guard = &g
	v.Injection = g.Injection
	return v
}

// Reason says briefly why a text was judged an injection.
func (v Verdict) Reason() string {
	if v.Guard != nil && v.Guard.Injection {
		return "the guard model says: " + v.Guard.Reason
	}
	for _, f := range v.Findings {
		if f.Severity == scan.High {
			return fmt.Sprintf("%s: %q", f.Check, f.Match)
		}
	}
	return ""
}

// Summary describes the verdict for the audit log, or "" if there's
// nothing to say.
func (v Verdict) Summary() string {
	var parts []string
	if v.Injection {
		parts = append(parts, "prompt injection ("+v.Reason()+")")
	}
	for _, f := range v.Findings {
		parts = append(parts, fmt.Sprintf("%s %s: %q", f.Severity, f.Check, f.Match))
	}
	if len(parts) == 0 {
		return "" // a clean result needs no note
	}
	switch g := v.Guard; {
	case g != nil && !g.Injection:
		parts = append(parts, "the guard model found no injection")
	case v.GuardErr != nil:
		parts = append(parts, "guard model unavailable")
	}
	if g := v.Guard; g != nil && g.Partial {
		parts = append(parts, "the guard model checked only part of the text")
	}
	return strings.Join(parts, "; ")
}
