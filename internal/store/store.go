// Package store keeps the device list for a two-person VPN.
// A subscription URL stays valid so Happ can refresh it, but the first
// x-hwid to fetch it locks the link. Other device ids are rejected.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"privatevpn/internal/atomicfile"
)

var (
	ErrNotFound     = errors.New("unknown subscription")
	ErrRevoked      = errors.New("device revoked")
	ErrHWIDRequired = errors.New("device id required")
	ErrBadHWID      = errors.New("bad device id")
	ErrHWIDMismatch = errors.New("device id mismatch")
	ErrLimit        = errors.New("device limit reached")
	ErrBadName      = errors.New("bad device name")
)

// hwidRe matches the Happ / Remnawave device id shape.
var hwidRe = regexp.MustCompile(`^[a-z0-9=-]{10,64}$`)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$`)

// Device is one phone, PC, or TV that may import the subscription.
type Device struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Token     string `json:"token"`
	UUID      string `json:"uuid"`
	HWID      string `json:"hwid,omitempty"`
	OS        string `json:"os,omitempty"`
	Model     string `json:"model,omitempty"`
	BoundAt   string `json:"bound_at,omitempty"`
	Revoked   bool   `json:"revoked"`
	CreatedAt string `json:"created_at"`
}

type fileData struct {
	Devices []Device `json:"devices"`
	NextID  int64    `json:"next_id"`
}

func (d fileData) clone() fileData {
	out := d
	out.Devices = append([]Device(nil), d.Devices...)
	return out
}

// Store is a JSON file guarded by a mutex. Six devices do not need a database.
type Store struct {
	mu   sync.Mutex
	path string
	data fileData
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, data: fileData{NextID: 1}}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("read devices: %w", err)
	}
	if s.data.NextID < 1 {
		s.data.NextID = 1
	}
	return s, nil
}

// Create adds an unbound device. max is the cap of non-revoked devices.
func (s *Store) Create(name string, max int) (Device, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return Device{}, ErrBadName
	}
	if max < 1 {
		return Device{}, ErrLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, d := range s.data.Devices {
		if !d.Revoked {
			active++
		}
	}
	if active >= max {
		return Device{}, ErrLimit
	}
	token, err := randomHex(32)
	if err != nil {
		return Device{}, err
	}
	id := s.data.NextID
	s.data.NextID++
	d := Device{
		ID:        id,
		Name:      name,
		Token:     token,
		UUID:      newUUID(),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	prev := s.data.clone()
	s.data.Devices = append(s.data.Devices, d)
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return Device{}, err
	}
	return d, nil
}

func (s *Store) List() ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Device(nil), s.data.Devices...), nil
}

// Active returns devices that Xray should still accept.
func (s *Store) Active() ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, 0, len(s.data.Devices))
	for _, d := range s.data.Devices {
		if !d.Revoked {
			out = append(out, d)
		}
	}
	return out, nil
}

// Claim binds token to hwid on the first call. The same hwid may refresh.
// A different hwid is rejected. An empty hwid does not bind.
func (s *Store) Claim(token, hwid, osName, model string) (Device, error) {
	hwid, err := NormalizeHWID(hwid)
	if err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.indexToken(token)
	if !ok {
		return Device{}, ErrNotFound
	}
	d := s.data.Devices[i]
	if d.Revoked {
		return Device{}, ErrRevoked
	}
	if d.HWID == "" {
		d.HWID = hwid
		d.OS = clipMeta(osName)
		d.Model = clipMeta(model)
		d.BoundAt = time.Now().UTC().Format(time.RFC3339)
	} else if d.HWID != hwid {
		return Device{}, ErrHWIDMismatch
	} else {
		if osName != "" {
			d.OS = clipMeta(osName)
		}
		if model != "" {
			d.Model = clipMeta(model)
		}
	}
	prev := s.data.clone()
	s.data.Devices[i] = d
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return Device{}, err
	}
	return d, nil
}

// Unbind clears the device lock and rotates the VLESS uuid.
// The old key stops working once Xray reloads. The same URL can lock to a new device.
func (s *Store) Unbind(id int64) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.indexID(id)
	if !ok {
		return Device{}, ErrNotFound
	}
	d := s.data.Devices[i]
	if d.Revoked {
		return Device{}, ErrRevoked
	}
	d.UUID = newUUID()
	d.HWID = ""
	d.OS = ""
	d.Model = ""
	d.BoundAt = ""
	prev := s.data.clone()
	s.data.Devices[i] = d
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return Device{}, err
	}
	return d, nil
}

// Revoke removes the device from service. The slot frees up.
func (s *Store) Revoke(id int64) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.indexID(id)
	if !ok {
		return Device{}, ErrNotFound
	}
	d := s.data.Devices[i]
	d.Revoked = true
	prev := s.data.clone()
	s.data.Devices[i] = d
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return Device{}, err
	}
	return d, nil
}

// Delete removes the device record. Revoke only marks it, so the row stays until this.
func (s *Store) Delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.indexID(id)
	if !ok {
		return ErrNotFound
	}
	prev := s.data.clone()
	s.data.Devices = append(s.data.Devices[:i], s.data.Devices[i+1:]...)
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return err
	}
	return nil
}

// NormalizeHWID checks the Happ device id and returns it in lowercase.
func NormalizeHWID(hwid string) (string, error) {
	hwid = strings.ToLower(strings.TrimSpace(hwid))
	if hwid == "" {
		return "", ErrHWIDRequired
	}
	if !hwidRe.MatchString(hwid) {
		return "", ErrBadHWID
	}
	return hwid, nil
}

func (s *Store) indexToken(token string) (int, bool) {
	for i := range s.data.Devices {
		if s.data.Devices[i].Token == token {
			return i, true
		}
	}
	return 0, false
}

func (s *Store) indexID(id int64) (int, bool) {
	for i := range s.data.Devices {
		if s.data.Devices[i].ID == id {
			return i, true
		}
	}
	return 0, false
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicfile.Write(s.path, b)
}

func clipMeta(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read only fails when the OS CSPRNG is unavailable.
		panic("crypto/rand: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
