package httpapi

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"privatevpn/internal/session"
	"privatevpn/internal/store"
	"privatevpn/internal/sub"
	"privatevpn/internal/xray"
)

// Server is the admin panel and the Happ subscription endpoint.
type Server struct {
	Store        *store.Store
	PublicURL    string
	Address      string
	Reality      xray.Reality
	PasswordHash []byte
	Sessions     *session.Manager
	Sync         func() error
	MaxDevices   int
	LoginLimit   *Limiter
	SubLimit     *Limiter
	pages        *template.Template
}

// Handler returns the panel routes.
func (s *Server) Handler() http.Handler {
	if s.pages == nil {
		subFS, err := fs.Sub(webFS, "web")
		if err != nil {
			panic(err)
		}
		s.pages = template.Must(template.ParseFS(subFS, "*.html"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/panel.css", func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(webFS, "web/panel.css")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("GET /{$}", s.authed(s.home))
	mux.HandleFunc("POST /devices", s.authed(s.createDevice))
	mux.HandleFunc("POST /devices/{id}/unbind", s.authed(s.unbind))
	mux.HandleFunc("POST /devices/{id}/revoke", s.authed(s.revoke))
	mux.HandleFunc("POST /sync", s.authed(s.sync))
	mux.HandleFunc("GET /s/{token}", s.subscription)
	return secureHeaders(mux)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.Sessions.Valid(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", loginPage{Error: errText(r.URL.Query().Get("err"))})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "blocked request", http.StatusForbidden)
		return
	}
	if s.LoginLimit.Saturated(clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pass := r.FormValue("password")
	if len(pass) == 0 || len(pass) > 72 {
		s.failLogin(w, r)
		return
	}
	if err := bcrypt.CompareHashAndPassword(s.PasswordHash, []byte(pass)); err != nil {
		s.failLogin(w, r)
		return
	}
	s.Sessions.Set(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) failLogin(w http.ResponseWriter, r *http.Request) {
	if s.LoginLimit != nil && !s.LoginLimit.Allow(clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	http.Redirect(w, r, "/login?err=login", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Sessions.Clear(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.List()
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	active := 0
	rows := make([]row, 0, len(list))
	for _, d := range list {
		if !d.Revoked {
			active++
		}
		state := "Waiting for Happ"
		if d.Revoked {
			state = "Revoked"
		} else if d.HWID != "" {
			state = "Locked"
		}
		rows = append(rows, row{
			ID:      d.ID,
			Name:    d.Name,
			URL:     sub.URL(s.PublicURL, d.Token),
			State:   state,
			Detail:  detail(d),
			Revoked: d.Revoked,
		})
	}
	q := r.URL.Query()
	s.render(w, "panel.html", page{
		Error:   errText(q.Get("err")),
		Notice:  okText(q.Get("ok")),
		Address: s.Address,
		Port:    s.Reality.Port,
		Devices: rows,
		CanAdd:  active < s.MaxDevices,
		Max:     s.MaxDevices,
	})
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if _, err := s.Store.Create(r.FormValue("name"), s.MaxDevices); err != nil {
		code := "name"
		if errors.Is(err, store.ErrLimit) {
			code = "limit"
		}
		http.Redirect(w, r, "/?err="+code, http.StatusSeeOther)
		return
	}
	s.afterMutation(w, r, "/?ok=created")
}

func (s *Server) unbind(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.Redirect(w, r, "/?err=notfound", http.StatusSeeOther)
		return
	}
	if _, err := s.Store.Unbind(id); err != nil {
		http.Redirect(w, r, "/?err=notfound", http.StatusSeeOther)
		return
	}
	s.afterMutation(w, r, "/?ok=unbound")
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.Redirect(w, r, "/?err=notfound", http.StatusSeeOther)
		return
	}
	if _, err := s.Store.Revoke(id); err != nil {
		http.Redirect(w, r, "/?err=notfound", http.StatusSeeOther)
		return
	}
	s.afterMutation(w, r, "/?ok=revoked")
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request) {
	s.afterMutation(w, r, "/?ok=synced")
}

func (s *Server) afterMutation(w http.ResponseWriter, r *http.Request, dest string) {
	if err := s.syncXray(); err != nil {
		log.Printf("xray sync: %v", err)
		http.Redirect(w, r, "/?err=sync", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) syncXray() error {
	if s.Sync == nil {
		return errors.New("xray sync is not configured")
	}
	return s.Sync()
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	if s.SubLimit != nil && !s.SubLimit.Allow(clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	token := r.PathValue("token")
	if !validToken(token) {
		http.Error(w, "unknown subscription", http.StatusNotFound)
		return
	}
	w.Header().Set("X-Hwid-Active", "true")
	d, err := s.Store.Claim(token, r.Header.Get("X-Hwid"), r.Header.Get("X-Device-Os"), r.Header.Get("X-Device-Model"))
	if err != nil {
		writeSubErr(w, err)
		return
	}
	body, err := (sub.Link{
		Name:    d.Name,
		UUID:    d.UUID,
		Address: s.Address,
		Reality: s.Reality,
	}).Body()
	if err != nil {
		http.Error(w, "subscription unavailable", http.StatusInternalServerError)
		return
	}
	title := d.Name
	if len(title) > 25 {
		title = title[:25]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Always-Hwid-Enable", "1")
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Profile-Title", title)
	w.Header().Set("Content-Disposition", "attachment; filename=\"nl\"")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

func writeSubErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "unknown subscription", http.StatusNotFound)
	case errors.Is(err, store.ErrHWIDRequired), errors.Is(err, store.ErrBadHWID):
		w.Header().Set("X-Hwid-Not-Supported", "true")
		w.Header().Set("X-Hwid-Active", "true")
		http.Error(w, "Happ must send a device id (x-hwid). Nothing was locked. Enable HWID in Happ and open the link again.", http.StatusForbidden)
	case errors.Is(err, store.ErrHWIDMismatch):
		w.Header().Set("X-Hwid-Limit", "true")
		http.Error(w, "this subscription is locked to another device", http.StatusForbidden)
	case errors.Is(err, store.ErrRevoked):
		http.Error(w, "this device was revoked", http.StatusForbidden)
	default:
		http.Error(w, "subscription unavailable", http.StatusInternalServerError)
	}
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Sessions.Valid(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(w, "blocked request", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, false
	}
	return id, true
}

func validToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func detail(d store.Device) string {
	parts := make([]string, 0, 3)
	if d.OS != "" {
		parts = append(parts, d.OS)
	}
	if d.Model != "" {
		parts = append(parts, d.Model)
	}
	if d.HWID != "" {
		parts = append(parts, shortHWID(d.HWID))
	}
	return strings.Join(parts, " · ")
}

func shortHWID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

func errText(code string) string {
	switch code {
	case "login":
		return "Wrong password."
	case "name":
		return "Name must be 1–32 characters: letters, numbers, spaces, dot, underscore, or dash. Start with a letter or number."
	case "limit":
		return "Device cap reached. Revoke one first."
	case "sync":
		return "Saved, but Xray did not reload. Fix Xray, then press Sync."
	case "notfound":
		return "That device is gone."
	default:
		return ""
	}
}

func okText(code string) string {
	switch code {
	case "created":
		return "Device added. Open the link in Happ on the one device that should use it."
	case "unbound":
		return "Lock cleared and the key rotated. The next Happ device to open the link becomes the only one."
	case "revoked":
		return "Device revoked. It can no longer connect."
	case "synced":
		return "Xray reloaded."
	default:
		return ""
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Limiter is a small fixed-window counter keyed by client IP.
type Limiter struct {
	mu     sync.Mutex
	Limit  int
	Window time.Duration
	hits   map[string][]time.Time
}

// Saturated reports whether key is already at the limit. It does not record a hit.
func (l *Limiter) Saturated(key string) bool {
	if l == nil || l.Limit <= 0 {
		return false
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensure()
	kept := l.trim(key, now)
	l.store(key, kept)
	return len(kept) >= l.Limit
}

// Allow records one hit and reports whether it is still under the limit.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.Limit <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensure()
	kept := l.trim(key, now)
	if len(kept) >= l.Limit {
		l.store(key, kept)
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func (l *Limiter) ensure() {
	if l.hits == nil || len(l.hits) > 2048 {
		l.hits = map[string][]time.Time{}
	}
}

func (l *Limiter) trim(key string, now time.Time) []time.Time {
	old := l.hits[key]
	kept := make([]time.Time, 0, len(old))
	for _, ts := range old {
		if now.Sub(ts) < l.Window {
			kept = append(kept, ts)
		}
	}
	return kept
}

func (l *Limiter) store(key string, kept []time.Time) {
	if len(kept) == 0 {
		delete(l.hits, key)
		return
	}
	l.hits[key] = kept
}

type loginPage struct {
	Error string
}

type page struct {
	Error   string
	Notice  string
	Address string
	Port    int
	Devices []row
	CanAdd  bool
	Max     int
}

type row struct {
	ID      int64
	Name    string
	URL     string
	State   string
	Detail  string
	Revoked bool
}
