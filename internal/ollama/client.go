// Package ollama is a small client for the Ollama REST API
// (https://github.com/ollama/ollama/blob/main/docs/api.md).
//
// It covers only what portcullis-agent needs. Chat is streamed as
// newline-delimited JSON, so a long response can be cancelled the moment
// its context is.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// DefaultHost is where Ollama listens unless OLLAMA_HOST says otherwise.
const DefaultHost = "http://127.0.0.1:11434"

// Client talks to one Ollama server. It is safe for concurrent use.
type Client struct {
	base *url.URL
	http *http.Client
}

// NewClient returns a client for the server at host, which may omit the
// scheme and port ("localhost", "192.0.2.10:11434", "https://ollama.example").
// An empty host means DefaultHost. If httpClient is nil, http.DefaultClient is used.
func NewClient(host string, httpClient *http.Client) (*Client, error) {
	u, err := parseHost(host)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		// No overall timeout: generations can legitimately take minutes.
		// Callers bound each request with a context instead.
		httpClient = http.DefaultClient
	}
	return &Client{base: u, http: httpClient}, nil
}

// FromEnv returns a client for the server named by $OLLAMA_HOST, the same
// variable the ollama CLI reads.
func FromEnv() (*Client, error) {
	return NewClient(os.Getenv("OLLAMA_HOST"), nil)
}

// Host returns the server's base URL.
func (c *Client) Host() string {
	return c.base.String()
}

func parseHost(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = DefaultHost
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid Ollama host %q: %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid Ollama host %q: scheme must be http or https", s)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid Ollama host %q: missing host name", s)
	}
	// Like the ollama CLI, a plain http host without a port means Ollama's default port.
	if u.Port() == "" && u.Scheme == "http" {
		u.Host = net.JoinHostPort(u.Hostname(), "11434")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// APIError is an error reported by the Ollama server.
type APIError struct {
	// StatusCode is the HTTP status, or 0 if the error arrived in the middle of a stream.
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.StatusCode == 0 {
		return "ollama: " + e.Message
	}
	return fmt.Sprintf("ollama: %s (HTTP %d)", e.Message, e.StatusCode)
}

// IsNotFound reports whether err means the requested model is not installed.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// do sends a request and returns the response if the server accepted it.
// The caller must close the response body.
func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.JoinPath(path).String(), r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot reach Ollama at %s; is it running? Start it with `ollama serve` or set OLLAMA_HOST: %w", c.base, err)
		}
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		defer resp.Body.Close()
		return nil, readError(resp)
	}
	return resp, nil
}

// readError turns an error response into an *APIError. Ollama sends
// {"error": "..."}; anything else is reported as raw text.
func readError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &body) == nil && body.Error != "" {
		msg = body.Error
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg}
}

// getJSON sends a request and decodes a single JSON response into out.
func (c *Client) getJSON(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("ollama: decoding %s response: %w", path, err)
	}
	return nil
}

// stream decodes a newline-delimited JSON body, calling fn for each object.
// Ollama reports failures that happen mid-stream as an {"error": "..."} object.
func stream[T any](body io.Reader, fn func(T) error) error {
	dec := json.NewDecoder(body)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("ollama: reading stream: %w", err)
		}

		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return &APIError{Message: e.Error}
		}

		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("ollama: decoding stream: %w", err)
		}
		if err := fn(v); err != nil {
			return err
		}
	}
}
