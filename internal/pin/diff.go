package pin

import (
	"encoding/json"
	"strings"
)

// Lines renders a definition as lines of text for review: the description
// line by line, the schemas as indented JSON.
func (d Definition) Lines() []string {
	var out []string
	add := func(name string, v any) {
		if v == nil {
			return
		}
		b, err := json.MarshalIndent(v, "  ", "  ")
		if err != nil {
			return
		}
		out = append(out, name+":")
		out = append(out, strings.Split("  "+string(b), "\n")...)
	}
	out = append(out, "name: "+d.Name)
	if d.Title != "" {
		out = append(out, "title: "+d.Title)
	}
	if d.Description != "" {
		out = append(out, "description:")
		for line := range strings.Lines(d.Description) {
			out = append(out, "  "+strings.TrimRight(line, "\r\n"))
		}
	}
	add("inputSchema", d.InputSchema)
	add("outputSchema", d.OutputSchema)
	if d.Annotations != nil {
		add("annotations", d.Annotations)
	}
	return out
}

// maxDiffCells caps the LCS table Diff builds. A server controls its tool
// definitions, so it could otherwise make reviewing them take all the
// reviewer's memory.
const maxDiffCells = 1 << 22

// Diff returns a line diff from before to after: unchanged lines start with
// two spaces, removed ones with "- " and added ones with "+ ".
func Diff(before, after []string) []string {
	// Lines the two share at the start and end are unchanged; only the
	// middle needs the LCS table.
	pre := 0
	for pre < len(before) && pre < len(after) && before[pre] == after[pre] {
		pre++
	}
	suf := 0
	for suf < len(before)-pre && suf < len(after)-pre && before[len(before)-1-suf] == after[len(after)-1-suf] {
		suf++
	}
	var out []string
	for _, l := range before[:pre] {
		out = append(out, "  "+l)
	}
	out = append(out, diffMiddle(before[pre:len(before)-suf], after[pre:len(after)-suf])...)
	for _, l := range before[len(before)-suf:] {
		out = append(out, "  "+l)
	}
	return out
}

func diffMiddle(before, after []string) []string {
	n, m := len(before), len(after)
	var out []string
	if n == 0 || m == 0 || n > maxDiffCells || m > maxDiffCells || n*m > maxDiffCells {
		// Nothing to align, or too much: show everything removed, then
		// everything added.
		for _, l := range before {
			out = append(out, "- "+l)
		}
		for _, l := range after {
			out = append(out, "+ "+l)
		}
		return out
	}
	// Longest common subsequence, by dynamic programming.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if before[i] == after[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && before[i] == after[j]:
			out = append(out, "  "+before[i])
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "- "+before[i])
			i++
		default:
			out = append(out, "+ "+after[j])
			j++
		}
	}
	return out
}

// Trim keeps n unchanged lines of context around each change in a diff
// from Diff, and replaces longer unchanged runs with "  ...".
func Trim(diff []string, n int) []string {
	keep := make([]bool, len(diff))
	for i, line := range diff {
		if strings.HasPrefix(line, "  ") {
			continue
		}
		for j := max(0, i-n); j <= min(len(diff)-1, i+n); j++ {
			keep[j] = true
		}
	}
	var out []string
	for i, line := range diff {
		switch {
		case keep[i]:
			out = append(out, line)
		case len(out) == 0 || out[len(out)-1] != "  ...":
			out = append(out, "  ...")
		}
	}
	return out
}
