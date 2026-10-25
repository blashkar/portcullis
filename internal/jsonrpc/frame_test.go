package jsonrpc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func readAll(t *testing.T, r *Reader) ([]string, error) {
	t.Helper()
	var got []string
	for {
		msg, err := r.Read()
		if err != nil {
			return got, err
		}
		got = append(got, string(msg))
	}
}

func TestReader(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "lines", in: "{\"a\":1}\n{\"b\":2}\n", want: []string{`{"a":1}`, `{"b":2}`}},
		{name: "crlf", in: "{\"a\":1}\r\n{\"b\":2}\r\n", want: []string{`{"a":1}`, `{"b":2}`}},
		{name: "no final newline", in: "{\"a\":1}\n{\"b\":2}", want: []string{`{"a":1}`, `{"b":2}`}},
		{name: "blank lines", in: "\n\n{\"a\":1}\n  \n\n", want: []string{`{"a":1}`}},
		{name: "empty", in: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAll(t, NewReader(strings.NewReader(tt.in), 0))
			if !errors.Is(err, io.EOF) {
				t.Fatalf("err = %v, want io.EOF", err)
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// A long message spans many reads of the 64 KiB buffer.
func TestReaderLongMessage(t *testing.T) {
	long := `{"x":"` + strings.Repeat("a", 300_000) + `"}`
	got, err := readAll(t, NewReader(strings.NewReader(long+"\n{}\n"), 0))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 || got[0] != long || got[1] != "{}" {
		t.Fatalf("got %d messages, want the long one and {}", len(got))
	}
}

// An oversized message is skipped and the next one still reads correctly.
func TestReaderTooLarge(t *testing.T) {
	in := "{\"ok\":1}\n" + strings.Repeat("x", 200_000) + "\n{\"ok\":2}\n"
	r := NewReader(strings.NewReader(in), 1000)

	want := []struct {
		msg string
		err error
	}{
		{msg: `{"ok":1}`},
		{err: ErrMessageTooLarge},
		{msg: `{"ok":2}`},
		{err: io.EOF},
	}
	for i, w := range want {
		msg, err := r.Read()
		if w.err != nil {
			if !errors.Is(err, w.err) {
				t.Fatalf("read %d: err = %v, want %v", i, err, w.err)
			}
			continue
		}
		if err != nil || string(msg) != w.msg {
			t.Fatalf("read %d: got %q, %v; want %q", i, msg, err, w.msg)
		}
	}
}

func TestWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Write([]byte("{\"a\":\n1}")); err == nil {
		t.Error("Write accepted a message containing a newline")
	}
	if got := buf.String(); got != "{\"a\":1}\n" {
		t.Errorf("wrote %q", got)
	}
}

// Concurrent writes must not interleave within a line.
func TestWriterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	msg := []byte(`{"x":"` + strings.Repeat("y", 10_000) + `"}`)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := w.Write(msg); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	got, err := readAll(t, NewReader(&buf, 0))
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Fatalf("read %d messages, want 20", len(got))
	}
	for _, m := range got {
		if m != string(msg) {
			t.Fatal("messages interleaved")
		}
	}
}

func FuzzReader(f *testing.F) {
	f.Add([]byte("{}\n\r\n{\"a\":1}"), 8)
	f.Add([]byte(strings.Repeat("z", 100)+"\n{}"), 10)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		limit = limit%4096 + 1
		if limit < 1 {
			limit += 4096
		}
		r := NewReader(bytes.NewReader(data), limit)
		for range len(data) + 2 {
			msg, err := r.Read()
			if errors.Is(err, io.EOF) {
				return
			}
			if errors.Is(err, ErrMessageTooLarge) {
				continue
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if bytes.IndexByte(msg, '\n') >= 0 || len(msg) > limit+2 {
				t.Fatalf("bad message %q (limit %d)", msg, limit)
			}
		}
		t.Fatal("reader didn't reach EOF")
	})
}
