// Package jsonrpc parses JSON-RPC 2.0 messages as MCP uses them and frames
// them for the stdio transport.
//
// The proxy has to forward messages exactly as it received them, so Parse
// keeps the id, params and result as raw JSON instead of decoding them.
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Kind is the role a message plays in the protocol.
type Kind int

// The kinds of message JSON-RPC 2.0 defines.
const (
	KindInvalid      Kind = iota
	KindRequest           // has a method and an id; expects a response
	KindNotification      // has a method and no id; gets no response
	KindResponse          // has an id and a result or an error
)

func (k Kind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindNotification:
		return "notification"
	case KindResponse:
		return "response"
	default:
		return "invalid"
	}
}

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Message is one JSON-RPC 2.0 message. Exactly one of the Request,
// Notification and Response shapes is valid; Kind reports which.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the error object of a failed response.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// ErrBatch is returned by Parse for a JSON array. MCP dropped JSON-RPC
// batching in the 2025-06-18 revision, so the proxy doesn't inspect batches.
var ErrBatch = errors.New("jsonrpc: batch messages are not supported")

// Parse decodes one message and checks that it's well formed.
func Parse(data []byte) (*Message, error) {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		return nil, ErrBatch
	}
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("jsonrpc: %w", err)
	}
	if m.JSONRPC != "2.0" {
		return nil, fmt.Errorf("jsonrpc: version is %q, want \"2.0\"", m.JSONRPC)
	}
	if m.Kind() == KindInvalid {
		return nil, errors.New("jsonrpc: message is not a request, notification or response")
	}
	return &m, nil
}

// Kind classifies the message by the fields it has.
func (m *Message) Kind() Kind {
	hasID := len(m.ID) > 0
	switch {
	case m.Method != "" && m.Result == nil && m.Error == nil:
		if hasID {
			return KindRequest
		}
		return KindNotification
	case m.Method == "" && hasID && (m.Result != nil) != (m.Error != nil):
		return KindResponse
	default:
		return KindInvalid
	}
}

// IDString returns the id as compact JSON, so the number 1 and the string
// "1" stay distinct. It is "" when the message has no id.
func (m *Message) IDString() string {
	if len(m.ID) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, m.ID); err != nil {
		return string(m.ID)
	}
	return buf.String()
}
