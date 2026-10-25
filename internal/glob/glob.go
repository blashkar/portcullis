// Package glob matches tool names against patterns in which "*" matches
// any run of characters, including "/" and "__", so no tool name can slip
// past a "*".
package glob

import (
	"errors"
	"regexp"
	"strings"
)

// Patterns is a compiled list of patterns.
type Patterns []*regexp.Regexp

// Compile compiles patterns. An empty pattern is an error.
func Compile(patterns []string) (Patterns, error) {
	out := make(Patterns, 0, len(patterns))
	for _, pat := range patterns {
		if pat == "" {
			return nil, errors.New("empty tool pattern")
		}
		parts := strings.Split(pat, "*")
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		out = append(out, regexp.MustCompile(`(?s)\A`+strings.Join(parts, ".*")+`\z`))
	}
	return out, nil
}

// Match reports whether name matches any of the patterns.
func (p Patterns) Match(name string) bool {
	for _, re := range p {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
