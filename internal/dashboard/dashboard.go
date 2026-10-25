// Package dashboard serves portcullis's local web dashboard: calls waiting
// for approval, tools held back, and live activity.
//
// It can approve tool calls, so it is locked down:
//
//   - It listens only on a loopback address (config refuses anything else).
//   - Every URL starts with a random token made when serve starts, so only
//     someone given the URL can use it; other web pages in the browser can't
//     guess it to read the page or submit its forms. No cookies are used:
//     cookies aren't separated by port, so another local web server could
//     receive them.
//   - Requests whose Host isn't the dashboard's own address are refused,
//     which stops DNS-rebinding attacks, and so are cross-site form posts.
//   - Pages forbid scripts, styles and connections from anywhere else, and
//     framing. The only script is the dashboard's own, embedded in the binary.
//   - Text from servers and the client is escaped, and characters that hide
//     or disguise text, such as bidi controls, are shown as their code points.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/pin"
)

//go:embed assets
var assets embed.FS

// Options configure a Server.
type Options struct {
	Hub       *Hub
	Approvals *approval.Broker // nil: no approvals
	Feed      *Feed            // nil: no activity
	// Held returns the tools being held back, with the reasons.
	Held func() map[string]string
	// Pins, if not nil, lets held tools be approved from the dashboard.
	Pins *pin.Store

	Version   string
	SessionID string
	Logger    *slog.Logger
}

// Server is the dashboard.
type Server struct {
	o     Options
	log   *slog.Logger
	token string
	tmpl  *template.Template

	// hosts are the Host headers the dashboard answers to.
	hosts map[string]bool
	// readTimeout bounds reading a request; tests shorten it.
	readTimeout time.Duration
}

// New returns a dashboard with a new random token.
func New(o Options) *Server {
	if o.Hub == nil {
		o.Hub = NewHub()
	}
	if o.Held == nil {
		o.Held = func() map[string]string { return nil }
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{"visible": visible}).ParseFS(assets, "assets/*.html"))
	return &Server{o: o, log: o.Logger, token: rand.Text(), tmpl: tmpl, readTimeout: 10 * time.Second}
}

// URL returns the dashboard's address, token included, once it listens on
// addr.
func (s *Server) URL(addr net.Addr) string {
	return "http://" + addr.String() + "/" + s.token + "/"
}

// Serve serves the dashboard on ln until ctx is done. The listener must be
// on a loopback address.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return fmt.Errorf("dashboard: %v isn't a loopback address", ln.Addr())
	}
	port := strconv.Itoa(addr.Port)
	s.hosts = map[string]bool{ln.Addr().String(): true, "localhost:" + port: true}

	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       s.readTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go s.watchHeld(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if srv.Shutdown(shutdown) != nil {
			_ = srv.Close()
		}
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// watchHeld tells the dashboards when the set of held tools changes. The
// gateway rechecks tools on its own schedule, so look every second.
func (s *Server) watchHeld(ctx context.Context) {
	last := s.o.Held()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if now := s.o.Held(); !maps.Equal(now, last) {
				last = now
				s.o.Hub.Notify()
			}
		}
	}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "assets")
	files := http.FileServerFS(static)

	mux.HandleFunc("GET /{token}", s.guard(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/"+s.token+"/", http.StatusSeeOther)
	}))
	mux.HandleFunc("GET /{token}/{$}", s.guard(s.page))
	mux.HandleFunc("GET /{token}/main", s.guard(s.main))
	mux.HandleFunc("GET /{token}/events", s.guard(s.events))
	mux.HandleFunc("GET /{token}/static/{file}", s.guard(func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("file") {
		case "style.css", "app.js":
			r.URL.Path = "/" + r.PathValue("file")
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	mux.HandleFunc("POST /{token}/approvals", s.guard(s.decide))
	mux.HandleFunc("POST /{token}/approve-tool", s.guard(s.approveTool))
	return securityHeaders(mux)
}

// securityHeaders sets headers on every response, including errors.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// guard checks the token, the Host header and, for posts, where the
// request came from.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.PathValue("token")), []byte(s.token)) != 1 {
			// The same answer as for any unknown path: nothing to learn.
			http.NotFound(w, r)
			return
		}
		if !s.hosts[r.Host] {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			// Browsers say where a post comes from. Tools like curl don't,
			// and can't be made to post by a web page.
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "cross-origin request", http.StatusForbidden)
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
				http.Error(w, "cross-site request", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) page(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "page", s.view())
}

func (s *Server) main(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "main", s.view())
}

func (s *Server) render(w http.ResponseWriter, name string, v pageView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, v); err != nil {
		s.log.Error("dashboard: rendering", "err", err)
	}
}

// events streams a "change" event whenever something on the page changed.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	ch, cancel, ok := s.o.Hub.subscribe()
	if !ok {
		http.Error(w, "too many open dashboards", http.StatusServiceUnavailable)
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	send := func(msg string) bool {
		if _, err := fmt.Fprint(w, msg); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(": connected\n\n") {
		return
	}
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if !send(": ping\n\n") {
				return
			}
		case <-ch:
			// Changes often come in bursts, such as a call and its result;
			// let a burst finish so the page refreshes once.
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ch:
			default:
			}
			if !send("event: change\ndata: \n\n") {
				return
			}
		}
	}
}

// decide approves or denies a waiting call.
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	if s.o.Approvals == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PostForm.Get("id")
	var approve bool
	switch r.PostForm.Get("decision") {
	case "approve":
		approve = true
	case "deny":
	default:
		http.Error(w, "decision must be approve or deny", http.StatusBadRequest)
		return
	}
	req, ok := s.o.Approvals.Get(id)
	if !ok {
		s.gone(w, "That call isn't waiting any more: it was decided, it expired, or the client gave up.")
		return
	}
	// A call whose arguments are too long to show in full can only be
	// denied: nobody should approve what they couldn't see.
	if approve && len(req.Args) > maxShownArgs {
		http.Error(w, "the arguments are too long to show in full, so the call can only be denied", http.StatusForbidden)
		return
	}
	if err := s.o.Approvals.Decide(id, approve); err != nil {
		s.gone(w, "That call isn't waiting any more: it was decided, it expired, or the client gave up.")
		return
	}
	s.log.Info("dashboard: call decided", "tool", req.Tool, "approved", approve)
	http.Redirect(w, r, "/"+s.token+"/", http.StatusSeeOther)
}

// approveTool approves a held tool's pending definition, as "portcullis pin
// approve" does. The form says which definition the person looked at; if
// the server changed it again since, nothing is approved.
func (s *Server) approveTool(w http.ResponseWriter, r *http.Request) {
	if s.o.Pins == nil {
		http.NotFound(w, r)
		return
	}
	name, hash := r.PostForm.Get("tool"), r.PostForm.Get("hash")
	// The check and the approval happen together under the pin file's
	// lock, so a definition offered in between can't be approved unseen.
	ok, err := s.o.Pins.ApproveHash(name, hash)
	if err != nil {
		http.Error(w, "approving failed", http.StatusInternalServerError)
		s.log.Error("dashboard: approving a tool", "tool", name, "err", err)
		return
	}
	if !ok {
		s.gone(w, "That tool isn't waiting for approval any more, or its definition changed again since the page was loaded. Look at it again before approving.")
		return
	}
	s.log.Info("dashboard: tool approved", "tool", name)
	s.o.Hub.Notify()
	http.Redirect(w, r, "/"+s.token+"/", http.StatusSeeOther)
}

// gone answers a decision that came too late, with a way back.
func (s *Server) gone(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	if err := s.tmpl.ExecuteTemplate(w, "gone", msg); err != nil {
		s.log.Error("dashboard: rendering", "err", err)
	}
}
