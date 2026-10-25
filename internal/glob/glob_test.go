package glob

import "testing"

func TestMatch(t *testing.T) {
	p, err := Compile([]string{"fs__*", "git__git_log", "*__get-env", "a*b*c"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"fs__read_file":       true,
		"fs__":                true,
		"fs__a/b\nc":          true,
		"xfs__read_file":      false,
		"git__git_log":        true,
		"git__git_logs":       false,
		"everything__get-env": true,
		"abc":                 true,
		"a__b__c":             true,
		"acb":                 false,
		"FS__read_file":       false,
	} {
		if got := p.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	if _, err := Compile([]string{"ok", ""}); err == nil {
		t.Error("empty pattern accepted")
	}
	var none Patterns
	if none.Match("x") {
		t.Error("no patterns matched something")
	}
}
