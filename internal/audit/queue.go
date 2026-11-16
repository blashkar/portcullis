package audit

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by Queue.Record after Close.
var ErrClosed = errors.New("audit: the queue is closed")

// maxBatch is the most events a Queue writes in one transaction.
const maxBatch = 256

// Queue writes events to a Store in the background, so recording one
// doesn't wait for the disk. It keeps their order. It doesn't drop events
// for lack of room: when it is full, Record waits, so a slow disk slows
// calls down rather than losing their record. Events still waiting when
// the process is killed are lost, as is one the database refuses.
type Queue struct {
	store *Store
	onErr func(error)
	ch    chan Event

	mu     sync.RWMutex // held for reading while sending, for writing to close
	closed bool
	done   chan struct{}
}

// NewQueue starts a Queue that holds up to size events waiting to be
// written. onErr, if not nil, is told about each failed write.
func NewQueue(s *Store, size int, onErr func(error)) *Queue {
	q := &Queue{store: s, onErr: onErr, ch: make(chan Event, max(size, 1)), done: make(chan struct{})}
	go q.run()
	return q
}

// Record queues an event to be written. It waits while the queue is full,
// unless ctx ends first.
func (q *Queue) Record(ctx context.Context, e Event) error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return ErrClosed
	}
	select {
	case q.ch <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close writes the events still queued and stops the Queue. Record calls
// after Close fail with ErrClosed.
func (q *Queue) Close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()
	<-q.done
}

func (q *Queue) report(err error) {
	if err != nil && q.onErr != nil {
		q.onErr(err)
	}
}

func (q *Queue) run() {
	defer close(q.done)
	batch := make([]Event, 0, maxBatch)
	for e := range q.ch {
		batch = append(batch[:0], e)
	fill:
		for len(batch) < maxBatch {
			select {
			case e, ok := <-q.ch:
				if !ok {
					break fill
				}
				batch = append(batch, e)
			default:
				break fill
			}
		}
		// The events were accepted, so write them even if a caller's
		// context has ended since.
		if err := q.store.RecordBatch(context.Background(), batch); err == nil || len(batch) == 1 {
			q.report(err)
			continue
		}
		// One bad event fails the whole batch: write them one by one, so
		// only the ones that fail are lost.
		for _, e := range batch {
			q.report(q.store.Record(context.Background(), e))
		}
	}
}
