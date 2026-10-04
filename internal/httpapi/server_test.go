package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"privatevpn/internal/session"
	"privatevpn/internal/store"
	"privatevpn/internal/xray"
)

func TestSubscriptionLocksToFirstDeviceAndRefreshes(t *testing.T) {
	f := newFixture(t, 6)
	cookie := f.login(t)

	res := f.do(t, http.MethodPost, "/devices", url.Values{"name": {"Phone"}}, cookie)
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "ok=created") {
		t.Fatalf("create: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	_ = res.Body.Close()

	list, err := f.store.List()
	if err != nil || len(list) != 1 {
		t.Fatal(err, list)
	}
	d := list[0]
	res = f.do(t, http.MethodGet, "/", nil, cookie)
	page := readAll(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, d.Token) || !strings.Contains(page, "Phone") {
		t.Fatalf("panel: %d %s", res.StatusCode, page)
	}
	path := "/s/" + d.Token

	res = f.do(t, http.MethodGet, path, nil, nil)
	body := readAll(t, res)
	if res.StatusCode != http.StatusForbidden || strings.Contains(body, "vless://") {
		t.Fatalf("missing hwid should not return a profile: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("X-Hwid-Not-Supported") != "true" {
		t.Fatal("expected hwid not supported header")
	}
	still, _ := f.store.List()
	if still[0].HWID != "" {
		t.Fatal("missing hwid bound the device")
	}

	res = f.doHeaders(t, http.MethodGet, path, nil, nil, map[string]string{
		"X-Hwid":         "UE42LJXu4DbiCaBv",
		"X-Device-Os":    "iOS",
		"X-Device-Model": "iPhone",
	})
	body = readAll(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first device: %d %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "vless://"+d.UUID+"@") || strings.Contains(body, f.reality.PrivateKey) {
		t.Fatalf("bad subscription body: %s", body)
	}
	if res.Header.Get("Subscription-Always-Hwid-Enable") != "1" {
		t.Fatal("happ hwid header missing")
	}
	if !strings.Contains(body, "#profile-update-interval: 12") {
		t.Fatal("refresh directive missing")
	}

	res = f.doHeaders(t, http.MethodGet, path, nil, nil, map[string]string{"X-Hwid": "ue42ljxu4dbicabv"})
	body = readAll(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, d.UUID) {
		t.Fatalf("refresh: %d %s", res.StatusCode, body)
	}

	res = f.doHeaders(t, http.MethodGet, path, nil, nil, map[string]string{"X-Hwid": "OtherDevice99"})
	body = readAll(t, res)
	if res.StatusCode != http.StatusForbidden || strings.Contains(body, "vless://") {
		t.Fatalf("second device: %d %s", res.StatusCode, body)
	}

	res = f.do(t, http.MethodPost, "/devices/1/unbind", nil, cookie)
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "ok=unbound") {
		t.Fatalf("unbind: %d %s", res.StatusCode, loc)
	}
	_ = res.Body.Close()
	ids := f.synced(t)
	if len(ids) != 1 || ids[0] == d.UUID {
		t.Fatalf("xray still has old uuid: %v", ids)
	}

	res = f.do(t, http.MethodPost, "/devices/1/revoke", nil, cookie)
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "ok=revoked") {
		t.Fatalf("revoke: %s", loc)
	}
	_ = res.Body.Close()
	if ids = f.synced(t); len(ids) != 0 {
		t.Fatalf("revoked uuid still in xray: %v", ids)
	}
	res = f.doHeaders(t, http.MethodGet, path, nil, nil, map[string]string{"X-Hwid": "zzzzzzzzzz9999"})
	body = readAll(t, res)
	if res.StatusCode != http.StatusForbidden || strings.Contains(body, "vless://") {
		t.Fatalf("revoked fetch: %d %s", res.StatusCode, body)
	}
}

func TestPanelRequiresLoginAndOrigin(t *testing.T) {
	f := newFixture(t, 6)
	res := f.do(t, http.MethodGet, "/", nil, nil)
	if res.StatusCode != http.StatusSeeOther || !strings.HasSuffix(res.Header.Get("Location"), "/login") {
		t.Fatalf("home: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	_ = res.Body.Close()

	res = f.doNoOrigin(t, http.MethodPost, "/login", url.Values{"password": {"test-password-1"}})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("login without origin: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	cookie := f.login(t)
	res = f.doNoOrigin(t, http.MethodPost, "/devices", url.Values{"name": {"Phone"}})
	res.Request.AddCookie(cookie)
	// doNoOrigin does not add the cookie. Repeat with cookie and no origin.
	_ = res.Body.Close()
	req, err := http.NewRequest(http.MethodPost, f.ts.URL+"/devices", strings.NewReader(url.Values{"name": {"Phone"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	res, err = f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("post without origin: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	res = f.do(t, http.MethodGet, "/healthz", nil, nil)
	if body := readAll(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "ok") {
		t.Fatalf("health: %d %s", res.StatusCode, body)
	}
	res = f.do(t, http.MethodGet, "/static/panel.css", nil, nil)
	if body := readAll(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "color-scheme") {
		t.Fatalf("css: %d %s", res.StatusCode, body)
	}
}

func TestLoginRateLimit(t *testing.T) {
	f := newFixture(t, 6)
	f.srv.LoginLimit = &Limiter{Limit: 2, Window: time.Hour}
	for i := 0; i < 2; i++ {
		res := f.do(t, http.MethodPost, "/login", url.Values{"password": {"nope-nope-no"}}, nil)
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("attempt %d: %d", i, res.StatusCode)
		}
		_ = res.Body.Close()
	}
	res := f.do(t, http.MethodPost, "/login", url.Values{"password": {"nope-nope-no"}}, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestDeviceCap(t *testing.T) {
	f := newFixture(t, 1)
	cookie := f.login(t)
	res := f.do(t, http.MethodPost, "/devices", url.Values{"name": {"One"}}, cookie)
	_ = res.Body.Close()
	res = f.do(t, http.MethodPost, "/devices", url.Values{"name": {"Two"}}, cookie)
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "err=limit") {
		t.Fatalf("cap: %d %s", res.StatusCode, loc)
	}
	_ = res.Body.Close()
}

func TestSyncFailureStaysVisible(t *testing.T) {
	f := newFixture(t, 6)
	f.failSync.Store(true)
	cookie := f.login(t)
	res := f.do(t, http.MethodPost, "/devices", url.Values{"name": {"Phone"}}, cookie)
	if !strings.Contains(res.Header.Get("Location"), "err=sync") {
		t.Fatalf("sync error: %s", res.Header.Get("Location"))
	}
	_ = res.Body.Close()
	list, err := f.store.List()
	if err != nil || len(list) != 1 {
		t.Fatal(err, list)
	}
}

type fixture struct {
	ts       *httptest.Server
	client   *http.Client
	store    *store.Store
	srv      *Server
	reality  xray.Reality
	mu       sync.Mutex
	ids      []string
	failSync atomic.Bool
}

func newFixture(t *testing.T, max int) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := xray.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		store: st,
		reality: xray.Reality{
			Port:        443,
			Dest:        "www.microsoft.com:443",
			ServerNames: []string{"www.microsoft.com"},
			PrivateKey:  priv,
			PublicKey:   pub,
			ShortIDs:    []string{"0123abcd"},
			Fingerprint: "chrome",
		},
	}
	f.srv = &Server{
		Store:        st,
		PublicURL:    "https://vpn.example.com:8443",
		Address:      "203.0.113.10",
		Reality:      f.reality,
		PasswordHash: hash,
		Sessions:     session.New([]byte("0123456789abcdef0123456789abcdef"), false),
		MaxDevices:   max,
		Sync: func() error {
			if f.failSync.Load() {
				return errBoom
			}
			active, err := st.Active()
			if err != nil {
				return err
			}
			ids := make([]string, len(active))
			for i, d := range active {
				ids[i] = d.UUID
			}
			f.mu.Lock()
			f.ids = ids
			f.mu.Unlock()
			return nil
		},
	}
	f.ts = httptest.NewServer(f.srv.Handler())
	t.Cleanup(f.ts.Close)
	f.client = f.ts.Client()
	f.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return f
}

var errBoom = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

func (f *fixture) login(t *testing.T) *http.Cookie {
	t.Helper()
	res := f.do(t, http.MethodPost, "/login", url.Values{"password": {"test-password-1"}}, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "pv_session" {
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}

func (f *fixture) do(t *testing.T, method, path string, form url.Values, cookie *http.Cookie) *http.Response {
	t.Helper()
	return f.doHeaders(t, method, path, form, cookie, map[string]string{"Origin": f.ts.URL})
}

func (f *fixture) doNoOrigin(t *testing.T, method, path string, form url.Values) *http.Response {
	t.Helper()
	return f.doHeaders(t, method, path, form, nil, nil)
}

func (f *fixture) doHeaders(t *testing.T, method, path string, form url.Values, cookie *http.Cookie, headers map[string]string) *http.Response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, f.ts.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (f *fixture) synced(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
