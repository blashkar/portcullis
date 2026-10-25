package jsonrpc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// DefaultMaxMessageSize caps a single message. Tool results such as file
// contents can be large, but an unbounded line would let a misbehaving peer
// exhaust the proxy's memory.
const DefaultMaxMessageSize = 32 << 20 // 32 MiB

// ErrMessageTooLarge is returned when a line exceeds the reader's limit.
var ErrMessageTooLarge = errors.New("jsonrpc: message exceeds size limit")

// Reader reads newline-delimited messages, the framing the MCP stdio
// transport uses: one JSON message per line, no embedded newlines.
type Reader struct {
	r   *bufio.Reader
	max int
}

// NewReader returns a Reader that rejects messages longer than maxSize bytes.
// maxSize <= 0 means DefaultMaxMessageSize.
func NewReader(r io.Reader, maxSize int) *Reader {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &Reader{r: bufio.NewReaderSize(r, 64<<10), max: maxSize}
}

// Read returns the next message without its line ending, skipping blank
// lines. It returns io.EOF once the stream ends, including a final line that
// has no newline. The returned slice is owned by the caller.
func (r *Reader) Read() ([]byte, error) {
	for {
		line, err := r.readLine()
		if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
			return nil, err
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) > 0 {
			return line, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// readLine reads up to and including '\n', enforcing the size limit while
// reading so an oversized line is never fully buffered.
func (r *Reader) readLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.r.ReadSlice('\n')
		if len(line)+len(chunk) > r.max+2 { // +2 for "\r\n"
			r.discardLine(err)
			return nil, fmt.Errorf("%w (%d bytes)", ErrMessageTooLarge, r.max)
		}
		line = append(line, chunk...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// discardLine skips the rest of an oversized line so the stream stays in
// sync. err is the error from the read that hit the limit.
func (r *Reader) discardLine(err error) {
	for errors.Is(err, bufio.ErrBufferFull) {
		_, err = r.r.ReadSlice('\n')
	}
}

// Writer writes newline-delimited messages. It's safe for concurrent use, so
// several goroutines can reply on the same stream without interleaving.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter returns a Writer on w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Write writes msg followed by a newline in a single call.
func (w *Writer) Write(msg []byte) error {
	if bytes.IndexByte(msg, '\n') >= 0 {
		return errors.New("jsonrpc: message contains a newline")
	}
	buf := make([]byte, 0, len(msg)+1)
	buf = append(buf, msg...)
	buf = append(buf, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(buf)
	return err
}
