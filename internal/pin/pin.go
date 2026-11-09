// Package pin detects rug pulls: an MCP server changing a tool's, prompt's
// or resource's definition after it was trusted.
//
// A server can behave for a while and then swap a tool's description for
// one carrying instructions to the model, or widen its schema. The model
// reads the new definition with no sign anything changed. Prompts and
// resources have descriptions the client may show the model too. A Store
// keeps the approved definition of each of them in a JSON file; one whose
// definition no longer matches is held back until a person approves the
// change.
//
// The file is meant to be read and diffed, and can be committed alongside
// the config, like a lockfile.
package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Kinds of definition, other than tools.
const (
	KindPrompt   = "prompt"
	KindResource = "resource"
)

// Definition is the part of a tool, prompt or resource that the model sees
// and a pin covers. Icons and _meta are left out: they don't change what
// the model is told. Neither are a resource's size and annotations, which
// change with its contents.
//
// Fields a tool doesn't have are omitted from its JSON, so a tool's hash is
// what it was before prompts and resources were pinned.
type Definition struct {
	Kind         string                `json:"kind,omitempty"` // "" for a tool
	Name         string                `json:"name"`
	URI          string                `json:"uri,omitempty"`
	Title        string                `json:"title,omitempty"`
	Description  string                `json:"description,omitempty"`
	MIMEType     string                `json:"mimeType,omitempty"`
	Arguments    []*mcp.PromptArgument `json:"arguments,omitempty"`
	InputSchema  any                   `json:"inputSchema,omitempty"`
	OutputSchema any                   `json:"outputSchema,omitempty"`
	Annotations  *mcp.ToolAnnotations  `json:"annotations,omitempty"`
}

// FromTool returns a tool's definition, as the server named it.
func FromTool(t *mcp.Tool) Definition {
	return Definition{
		Name: t.Name, Title: t.Title, Description: t.Description,
		InputSchema: t.InputSchema, OutputSchema: t.OutputSchema, Annotations: t.Annotations,
	}
}

// FromPrompt returns a prompt's definition.
func FromPrompt(p *mcp.Prompt) Definition {
	return Definition{Kind: KindPrompt, Name: p.Name, Title: p.Title, Description: p.Description, Arguments: p.Arguments}
}

// FromResource returns a resource's definition.
func FromResource(r *mcp.Resource) Definition {
	return Definition{
		Kind: KindResource, Name: r.Name, URI: r.URI, Title: r.Title,
		Description: r.Description, MIMEType: r.MIMEType,
	}
}

// Key is the name a definition is pinned under: a tool's name, or for a
// prompt or a resource its name or URI after "prompt:" or "resource:".
// Tool names start with their server's name, which can't contain a colon,
// so the three never collide.
func (d Definition) Key() string {
	switch d.Kind {
	case KindPrompt:
		return KindPrompt + ":" + d.Name
	case KindResource:
		return KindResource + ":" + d.URI
	}
	return d.Name
}

// KindOf returns the kind of definition pinned under key: "tool",
// KindPrompt or KindResource.
func KindOf(key string) string {
	for _, k := range []string{KindPrompt, KindResource} {
		if strings.HasPrefix(key, k+":") {
			return k
		}
	}
	return "tool"
}

// Hash returns a hash of the definition. JSON objects are encoded with
// sorted keys, so the same definition always hashes the same.
func (d Definition) Hash() string {
	b, err := json.Marshal(d)
	if err != nil {
		// Schemas come from JSON, so they always encode.
		panic(fmt.Sprintf("pin: encoding a definition: %v", err))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Entry is one tool's, prompt's or resource's record in the pin file.
type Entry struct {
	// Hash and Definition are the approved definition; both are empty if
	// it has never been approved.
	Hash       string      `json:"hash,omitempty"`
	Definition *Definition `json:"definition,omitempty"`
	Approved   time.Time   `json:"approved,omitzero"`
	// Pending is a different definition the server has offered since.
	Pending *Pending `json:"pending,omitempty"`
}

// Pending is a definition waiting for approval.
type Pending struct {
	Hash       string     `json:"hash"`
	Definition Definition `json:"definition"`
	Seen       time.Time  `json:"seen"`
}

// Status is how a current definition compares with its pin.
type Status int

// Statuses.
const (
	Approved Status = iota + 1 // matches the approved definition
	Pinned                     // first seen just now, and pinned
	Changed                    // differs from the approved definition: held
	New                        // never approved, and new tools are held: held
)

func (s Status) String() string {
	return [...]string{"", "approved", "pinned", "changed", "new"}[s]
}

// Held reports whether a definition in this state must not be offered.
func (s Status) Held() bool {
	return s == Changed || s == New
}

// file is the pin file. Tools holds prompts and resources too, under their
// keys, so pin files written before those were pinned still read.
type file struct {
	Version int               `json:"version"`
	Tools   map[string]*Entry `json:"tools"`
}

const fileVersion = 1

// Store is a pin file. It is safe for concurrent use, and for use by
// several processes at once: changes are made under a lock on the file and
// written atomically.
type Store struct {
	path    string
	holdNew bool
	now     func() time.Time

	mu  sync.Mutex
	sum [32]byte // the file's content when this Store last read or wrote it
}

// Open returns the Store for the pin file at path, which needn't exist
// yet. If holdNew is set, definitions never seen before are held for
// approval instead of being pinned on first sight.
func Open(path string, holdNew bool) *Store {
	// Until the Store reads the file, compare with a missing one.
	return &Store{path: path, holdNew: holdNew, now: time.Now, sum: sha256.Sum256(nil)}
}

// Path returns the pin file's path.
func (s *Store) Path() string {
	return s.path
}

// Check compares the definitions a server offers, keyed by Key, with the
// pinned ones. New definitions are pinned (or held), and a changed one is
// recorded as pending so it can be reviewed.
func (s *Store) Check(defs map[string]Definition) (map[string]Status, error) {
	out := make(map[string]Status, len(defs))
	err := s.update(func(f *file) bool {
		dirty := false
		now := s.now().UTC()
		for name, def := range defs {
			h := def.Hash()
			e := f.Tools[name]
			switch {
			case e == nil && !s.holdNew:
				f.Tools[name] = &Entry{Hash: h, Definition: &def, Approved: now}
				out[name] = Pinned
				dirty = true
			case e != nil && e.Hash == h:
				out[name] = Approved
				if e.Pending != nil {
					// The server went back to the approved definition.
					e.Pending = nil
					dirty = true
				}
			default:
				if e == nil {
					e = &Entry{}
					f.Tools[name] = e
				}
				out[name] = Changed
				if e.Hash == "" {
					out[name] = New
				}
				if e.Pending == nil || e.Pending.Hash != h {
					e.Pending = &Pending{Hash: h, Definition: def, Seen: now}
					dirty = true
				}
			}
		}
		return dirty
	})
	return out, err
}

// Approve approves the pending definitions under the named keys, or every
// pending definition if names is empty. It returns the keys it approved,
// and an error naming any named key that had nothing to approve.
func (s *Store) Approve(names []string) ([]string, error) {
	explicit := len(names) > 0
	var approved, nothing []string
	err := s.update(func(f *file) bool {
		if !explicit {
			names = slices.Sorted(maps.Keys(f.Tools))
		}
		now := s.now().UTC()
		for _, name := range names {
			e := f.Tools[name]
			if e == nil || e.Pending == nil {
				if explicit {
					nothing = append(nothing, name)
				}
				continue
			}
			def := e.Pending.Definition
			e.Hash, e.Definition, e.Approved, e.Pending = e.Pending.Hash, &def, now, nil
			approved = append(approved, name)
		}
		return len(approved) > 0
	})
	if err != nil {
		return nil, err
	}
	if len(nothing) > 0 {
		return approved, fmt.Errorf("nothing waiting for approval: %s", strings.Join(nothing, ", "))
	}
	return approved, nil
}

// ApproveHash approves a key's pending definition only if its hash is
// hash: the definition a person looked at, not one the server offered
// since. It reports whether it approved anything.
func (s *Store) ApproveHash(name, hash string) (bool, error) {
	var ok bool
	err := s.update(func(f *file) bool {
		e := f.Tools[name]
		if e == nil || e.Pending == nil || e.Pending.Hash != hash {
			return false
		}
		def := e.Pending.Definition
		e.Hash, e.Definition, e.Approved, e.Pending = e.Pending.Hash, &def, s.now().UTC(), nil
		ok = true
		return true
	})
	return ok, err
}

// Entries returns every entry, by key.
func (s *Store) Entries() (map[string]*Entry, error) {
	var out map[string]*Entry
	err := s.update(func(f *file) bool {
		out = f.Tools
		return false
	})
	return out, err
}

// Modified reports whether the file has changed since this Store last read
// or wrote it, as it does when another process approves a change.
func (s *Store) Modified() bool {
	data, err := os.ReadFile(s.path)
	if err != nil {
		data = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return sha256.Sum256(data) != s.sum
}

// update reads the file under its lock, lets fn change it, and writes it
// back if fn reports a change.
func (s *Store) update(fn func(*file) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return fmt.Errorf("pin: locking %s: %w", s.path, err)
	}
	defer unlock()

	data, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pin: %w", err)
	}
	f := file{Version: fileVersion, Tools: map[string]*Entry{}}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("pin: reading %s: %w", s.path, err)
		}
		if f.Version != fileVersion {
			return fmt.Errorf("pin: %s has version %d; this portcullis reads version %d", s.path, f.Version, fileVersion)
		}
		if f.Tools == nil {
			f.Tools = map[string]*Entry{}
		}
	}
	s.sum = sha256.Sum256(data)
	if !fn(&f) {
		return nil
	}

	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	out = append(out, '\n')
	if err := writeAtomic(s.path, out); err != nil {
		return fmt.Errorf("pin: writing %s: %w", s.path, err)
	}
	s.sum = sha256.Sum256(out)
	return nil
}

// writeAtomic replaces path with data, so a reader never sees half a file.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
