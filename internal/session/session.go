package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "pv_session"

// Manager issues an HMAC session cookie for the single admin.
type Manager struct {
	secret []byte
	secure bool
	ttl    time.Duration
	now    func() time.Time
}

func New(secret []byte, secure bool) *Manager {
	return &Manager{secret: append([]byte(nil), secret...), secure: secure, ttl: 24 * time.Hour, now: time.Now}
}

func (m *Manager) Set(w http.ResponseWriter) {
	exp := m.now().Add(m.ttl).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    m.sign(exp),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
}

func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (m *Manager) Valid(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	exp, ok := m.open(c.Value)
	if !ok {
		return false
	}
	return m.now().Unix() < exp
}

func (m *Manager) sign(exp int64) string {
	payload := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(payload))
	return b64([]byte(payload)) + "." + b64(mac.Sum(nil))
}

func (m *Manager) open(val string) (int64, bool) {
	payloadB64, sigB64, ok := strings.Cut(val, ".")
	if !ok {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return 0, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return 0, false
	}
	exp, err := strconv.ParseInt(string(payload), 10, 64)
	if err != nil {
		return 0, false
	}
	return exp, true
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
