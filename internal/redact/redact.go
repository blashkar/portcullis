// Package redact removes secrets from text before it reaches the model.
//
// A tool result goes into the model's context, and from there into logs,
// transcripts and, for a cloud model, someone else's servers. A file or
// command output that happens to contain a key shouldn't carry it along.
// Each secret is replaced by a marker naming its kind:
// "[REDACTED:github_token]".
package redact

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Rule is one kind of secret.
type Rule struct {
	Name string
	// Pattern matches the secret. If it has a group named "secret", only
	// that part is replaced, so "password: hunter22" keeps its label.
	Pattern *regexp.Regexp
}

// DefaultRules are the secrets redacted out of the box. They favor
// formats with a distinctive shape, which rarely match anything else.
var DefaultRules = []Rule{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|\z)`)},
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"aws_secret_key", regexp.MustCompile(`(?i)aws_?secret_?(access_?)?key["']?\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9/+=]{40})\b`)},
	{"github_token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"openai_key", regexp.MustCompile(`\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{40,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"stripe_key", regexp.MustCompile(`\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"url_password", regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<secret>[^\s@/]{3,})@`)},
	// key = value pairs whose key says it's a secret. The value must be at
	// least 8 characters with no spaces, which skips prose like "the
	// password is required".
	{"secret_assignment", regexp.MustCompile(`(?i)\b[\w.-]*(password|passwd|pwd|secret|api_?key|access_?key|auth_?token|access_?token|client_?secret|private_?key)["']?\s*[:=]\s*["']?(?P<secret>[^\s"',;]{8,})`)},
}

// Redactor applies a set of rules. It is safe for concurrent use.
type Redactor struct {
	rules []Rule
}

// New returns a Redactor with the default rules followed by extra ones.
func New(extra ...Rule) *Redactor {
	return &Redactor{rules: append(slices.Clone(DefaultRules), extra...)}
}

// Counts records the distinct secrets redacted, by kind. The same secret
// redacted in two places, such as a tool result's text and its structured
// copy, counts once. Only hashes are kept, never the secrets.
type Counts map[string]map[[32]byte]bool

func (c Counts) add(kind, secret string) {
	if c[kind] == nil {
		c[kind] = map[[32]byte]bool{}
	}
	c[kind][sha256.Sum256([]byte(secret))] = true
}

// N returns the number of distinct secrets of a kind.
func (c Counts) N(kind string) int {
	return len(c[kind])
}

func (c Counts) String() string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(c)) {
		if n := len(c[k]); n == 1 {
			parts = append(parts, k)
		} else {
			parts = append(parts, fmt.Sprintf("%s×%d", k, n))
		}
	}
	return strings.Join(parts, ", ")
}

// Add adds other's secrets to c.
func (c Counts) Add(other Counts) {
	for k, set := range other {
		if c[k] == nil {
			c[k] = map[[32]byte]bool{}
		}
		maps.Copy(c[k], set)
	}
}

// String redacts s and counts what it replaced. Rules run in order, so a
// private key is replaced whole before a later rule can match inside it.
func (r *Redactor) String(s string) (string, Counts) {
	if r == nil {
		return s, nil
	}
	var counts Counts
	for _, rule := range r.rules {
		secret := rule.Pattern.SubexpIndex("secret")
		marker := "[REDACTED:" + rule.Name + "]"
		s = rule.Pattern.ReplaceAllStringFunc(s, func(m string) string {
			// Replace only the secret group if there is one, keeping the
			// label around it.
			start, end := 0, len(m)
			if secret >= 0 {
				if sub := rule.Pattern.FindStringSubmatchIndex(m); sub != nil && sub[2*secret] >= 0 {
					start, end = sub[2*secret], sub[2*secret+1]
				}
			}
			if strings.HasPrefix(m[start:], "[REDACTED:") {
				return m // an earlier rule got it
			}
			if counts == nil {
				counts = Counts{}
			}
			counts.add(rule.Name, m[start:end])
			return m[:start] + marker + m[end:]
		})
	}
	return s, counts
}

// Value redacts every string in a decoded JSON value, in place where it
// can, and returns the result.
func (r *Redactor) Value(v any, counts Counts) any {
	switch v := v.(type) {
	case string:
		out, c := r.String(v)
		counts.Add(c)
		return out
	case map[string]any:
		for k, x := range v {
			v[k] = r.Value(x, counts)
		}
		return v
	case []any:
		for i, x := range v {
			v[i] = r.Value(x, counts)
		}
		return v
	default:
		return v
	}
}
