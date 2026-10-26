package main

import "testing"

func TestClean(t *testing.T) {
	esc := string(rune(0x1b))
	in := "ok " + esc + "]0;pwned" + string(rune(0x07)) + esc + "[2J" + string(rune(0x9b)) + "31m done"
	in += " safe" + string(rune(0x202E)) + "txt.exe"
	want := "ok \uFFFD]0;pwned\uFFFD\uFFFD[2J\uFFFD31m done safe\uFFFDtxt.exe"
	if got := clean(in); got != want {
		t.Errorf("clean(%q) = %q, want %q", in, got, want)
	}
}
