package jsonrpc

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		kind    Kind
		id      string
		wantErr bool
	}{
		{name: "request", in: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, kind: KindRequest, id: "1"},
		{name: "string id", in: `{"jsonrpc":"2.0","id":"a-1","method":"ping"}`, kind: KindRequest, id: `"a-1"`},
		{name: "notification", in: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, kind: KindNotification},
		{name: "result", in: `{"jsonrpc":"2.0","id":1,"result":{}}`, kind: KindResponse, id: "1"},
		{name: "null result", in: `{"jsonrpc":"2.0","id":1,"result":null}`, kind: KindResponse, id: "1"},
		{name: "error", in: `{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}}`, kind: KindResponse, id: "2"},
		{name: "error with null id", in: `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}`, kind: KindResponse, id: "null"},
		{name: "whitespace in id", in: `{"jsonrpc":"2.0","id": [ 1 ],"method":"x"}`, kind: KindRequest, id: "[1]"},

		{name: "not json", in: `hello`, wantErr: true},
		{name: "wrong version", in: `{"jsonrpc":"1.0","id":1,"method":"x"}`, wantErr: true},
		{name: "no version", in: `{"id":1,"method":"x"}`, wantErr: true},
		{name: "empty object", in: `{"jsonrpc":"2.0"}`, wantErr: true},
		{name: "result and error", in: `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`, wantErr: true},
		{name: "response without id", in: `{"jsonrpc":"2.0","result":{}}`, wantErr: true},
		{name: "method and result", in: `{"jsonrpc":"2.0","id":1,"method":"x","result":{}}`, wantErr: true},
		{name: "batch", in: `[{"jsonrpc":"2.0","id":1,"method":"x"}]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.in))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%s) = %+v, want an error", tt.in, m)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%s): %v", tt.in, err)
			}
			if m.Kind() != tt.kind {
				t.Errorf("kind = %v, want %v", m.Kind(), tt.kind)
			}
			if m.IDString() != tt.id {
				t.Errorf("id = %q, want %q", m.IDString(), tt.id)
			}
		})
	}
}

func TestParseBatch(t *testing.T) {
	_, err := Parse([]byte(` [{"jsonrpc":"2.0","method":"x"}]`))
	if !errors.Is(err, ErrBatch) {
		t.Fatalf("err = %v, want ErrBatch", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"m"}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		if m.Kind() == KindInvalid {
			t.Fatalf("Parse accepted an invalid message: %q", data)
		}
		if m.Kind() != KindNotification && m.IDString() == "" {
			t.Fatalf("%v has no id: %q", m.Kind(), data)
		}
	})
}
