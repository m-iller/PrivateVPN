package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"privatevpn/internal/atomicfile"
)

// Reality is the public and private material for one VLESS inbound.
type Reality struct {
	Port        int      `json:"port"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	ShortIDs    []string `json:"short_ids"`
	Fingerprint string   `json:"fingerprint"`
}

// CDN is a VLESS over XHTTP and TLS inbound meant to sit behind a Cloudflare
// proxied hostname. Clients reach Cloudflare, not the VPS IP, so an IP block
// on the VPS does not cut them off. Cloudflare's "Full" SSL mode accepts the
// self-signed origin certificate.
type CDN struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Path     string `json:"path"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// Client is one VLESS user Xray will accept.
type Client struct {
	ID    string
	Email string
}

// Build returns an Xray config with one VLESS inbound: XHTTP+TLS when cdn is
// set, otherwise Reality.
func Build(r Reality, cdn *CDN, clients []Client) ([]byte, error) {
	if cdn != nil {
		if err := cdn.Validate(); err != nil {
			return nil, err
		}
	} else if err := r.Validate(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	outClients := make([]map[string]string, 0, len(clients))
	for _, c := range clients {
		if c.ID == "" || seen[c.ID] {
			return nil, fmt.Errorf("xray client id")
		}
		seen[c.ID] = true
		email := c.Email
		if email == "" {
			email = "device"
		}
		client := map[string]string{"id": c.ID, "email": email}
		if cdn == nil {
			// Vision needs raw TCP; XHTTP carries no flow.
			client["flow"] = "xtls-rprx-vision"
		}
		outClients = append(outClients, client)
	}
	inbound := map[string]any{
		"tag":      "vless-reality",
		"listen":   "0.0.0.0",
		"port":     r.Port,
		"protocol": "vless",
		"settings": map[string]any{
			"clients":    outClients,
			"decryption": "none",
		},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"show":         false,
				"dest":         r.Dest,
				"xver":         0,
				"serverNames":  r.ServerNames,
				"privateKey":   r.PrivateKey,
				"shortIds":     r.ShortIDs,
				"minClientVer": "1.0.0",
			},
		},
	}
	if cdn != nil {
		inbound["tag"] = "vless-xhttp"
		inbound["port"] = cdn.Port
		inbound["streamSettings"] = map[string]any{
			"network":  "xhttp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"alpn": []string{"h2", "http/1.1"},
				"certificates": []map[string]string{
					{"certificateFile": cdn.CertFile, "keyFile": cdn.KeyFile},
				},
			},
			"xhttpSettings": map[string]any{
				"path": cdn.Path,
				"mode": "auto",
			},
		}
	}
	doc := map[string]any{
		"log":      map[string]string{"loglevel": "warning"},
		"inbounds": []any{inbound},
		"outbounds": []any{
			map[string]string{"protocol": "freedom", "tag": "direct"},
		},
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

// WriteFile builds the config and replaces path.
func WriteFile(path string, r Reality, cdn *CDN, clients []Client) error {
	buf, err := Build(r, cdn, clients)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, buf); err != nil {
		return err
	}
	// 0640 so the xray user can read the file when the directory is setgid to group xray.
	return os.Chmod(path, 0o640)
}

// GenerateKeys returns an Xray-compatible X25519 pair (base64 raw url, 32 bytes).
func GenerateKeys() (privateKey, publicKey string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privateKey = base64.RawURLEncoding.EncodeToString(k.Bytes())
	publicKey = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

// RandomShortID returns 8 hex chars.
func RandomShortID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Validate checks the fields Xray needs for Reality.
func (r Reality) Validate() error {
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("reality port")
	}
	if !strings.Contains(r.Dest, ":") || strings.ContainsAny(r.Dest, " /") {
		return fmt.Errorf("reality dest")
	}
	if len(r.ServerNames) == 0 || r.ServerNames[0] == "" {
		return fmt.Errorf("reality server name")
	}
	if !validKey(r.PrivateKey) || !validKey(r.PublicKey) {
		return fmt.Errorf("reality key")
	}
	if len(r.ShortIDs) == 0 || !validShortID(r.ShortIDs[0]) {
		return fmt.Errorf("reality short id")
	}
	switch r.Fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "qq", "random", "randomized":
	default:
		return fmt.Errorf("reality fingerprint")
	}
	return nil
}

// Validate checks the fields Xray needs for the XHTTP inbound.
func (c CDN) Validate() error {
	if c.Host == "" || strings.ContainsAny(c.Host, " /:") || !strings.Contains(c.Host, ".") {
		return fmt.Errorf("cdn host")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("cdn port")
	}
	if len(c.Path) < 2 || c.Path[0] != '/' || strings.ContainsAny(c.Path, " ?#%") {
		return fmt.Errorf("cdn path")
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return fmt.Errorf("cdn certificate")
	}
	return nil
}

// RandomPath returns a hard-to-guess XHTTP path.
func RandomPath() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "/" + hex.EncodeToString(b[:]), nil
}

func validKey(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func validShortID(s string) bool {
	if len(s) < 2 || len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
