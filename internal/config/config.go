package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"privatevpn/internal/atomicfile"
	"privatevpn/internal/xray"
)

// Config is the on-disk panel configuration. It holds secrets. Mode 0600.
type Config struct {
	Listen            string       `json:"listen"`
	Domain            string       `json:"domain"`
	PublicURL         string       `json:"public_url"`
	ServerAddress     string       `json:"server_address"`
	DataDir           string       `json:"data_dir"`
	AdminPasswordHash string       `json:"admin_password_hash"`
	SessionSecret     string       `json:"session_secret"`
	XrayConfigPath    string       `json:"xray_config_path"`
	TLSMode           string       `json:"tls_mode"`
	MaxDevices        int          `json:"max_devices"`
	RestartXray       *bool        `json:"restart_xray,omitempty"`
	Reality           xray.Reality `json:"reality"`
}

// InitOptions are the flags for first-time setup.
type InitOptions struct {
	Path           string
	Address        string
	Domain         string
	PublicURL      string
	DataDir        string
	XrayConfigPath string
	Listen         string
	Password       string
}

// Init writes a new config and a starter Xray file. It refuses to overwrite.
// When Password is empty, a password is generated and written beside the config
// as admin.password. The password is not returned.
func Init(opt InitOptions) error {
	if _, err := os.Stat(opt.Path); err == nil {
		return fmt.Errorf("config already exists: %s", opt.Path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if opt.Listen == "" {
		opt.Listen = ":8443"
	}
	if opt.DataDir == "" {
		opt.DataDir = "/var/lib/privatevpn"
	}
	if opt.XrayConfigPath == "" {
		opt.XrayConfigPath = "/usr/local/etc/xray/config.json"
	}
	domain := strings.TrimSpace(opt.Domain)
	public := strings.TrimSpace(opt.PublicURL)
	tlsMode := "selfsigned"
	if domain != "" {
		tlsMode = "auto"
		if public == "" {
			public = "https://" + domain + ":8443"
		}
	}
	if public == "" {
		return fmt.Errorf("public url required when no domain is set")
	}
	password := opt.Password
	wroteFile := false
	if password == "" {
		var err error
		password, err = randomPassword()
		if err != nil {
			return err
		}
		wroteFile = true
	}
	if len(password) < 10 || len(password) > 72 {
		return fmt.Errorf("password length must be 10 to 72")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	priv, pub, err := xray.GenerateKeys()
	if err != nil {
		return err
	}
	sid, err := xray.RandomShortID()
	if err != nil {
		return err
	}
	cfg := Config{
		Listen:            opt.Listen,
		Domain:            domain,
		PublicURL:         strings.TrimRight(public, "/"),
		ServerAddress:     strings.TrimSpace(opt.Address),
		DataDir:           opt.DataDir,
		AdminPasswordHash: string(hash),
		SessionSecret:     hex.EncodeToString(secret),
		XrayConfigPath:    opt.XrayConfigPath,
		TLSMode:           tlsMode,
		MaxDevices:        6,
		Reality: xray.Reality{
			Port:        443,
			Dest:        "dl.google.com:443",
			ServerNames: []string{"www.microsoft.com"},
			PrivateKey:  priv,
			PublicKey:   pub,
			ShortIDs:    []string{sid},
			Fingerprint: "chrome",
		},
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.Path), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(opt.DataDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.XrayConfigPath), 0o750); err != nil {
		return err
	}
	if err := xray.WriteFile(opt.XrayConfigPath, cfg.Reality, nil); err != nil {
		return err
	}
	if err := cfg.Save(opt.Path); err != nil {
		return err
	}
	if wroteFile {
		passPath := filepath.Join(filepath.Dir(opt.Path), "admin.password")
		if err := atomicfile.Write(passPath, []byte(password+"\n")); err != nil {
			return err
		}
	}
	return nil
}

// Load reads a config file.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save writes the config with mode 0600.
func (c Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicfile.Write(path, b)
}

// Validate fails closed on missing secrets or a bad public URL.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen")
	}
	if c.MaxDevices < 1 || c.MaxDevices > 32 {
		return fmt.Errorf("max devices")
	}
	if err := validatePublicURL(c.PublicURL, c.TLSMode); err != nil {
		return err
	}
	if !validHost(c.ServerAddress) {
		return fmt.Errorf("server address")
	}
	switch c.TLSMode {
	case "off", "selfsigned":
	case "auto":
		if c.Domain == "" || !validHost(c.Domain) {
			return fmt.Errorf("domain")
		}
	default:
		return fmt.Errorf("tls mode")
	}
	if _, err := c.SessionKey(); err != nil {
		return err
	}
	if !strings.HasPrefix(c.AdminPasswordHash, "$2") {
		return fmt.Errorf("admin password hash")
	}
	if c.DataDir == "" || c.XrayConfigPath == "" {
		return fmt.Errorf("paths")
	}
	return c.Reality.Validate()
}

// SessionKey decodes the hex session secret.
func (c Config) SessionKey() ([]byte, error) {
	b, err := hex.DecodeString(c.SessionSecret)
	if err != nil || len(b) < 32 {
		return nil, fmt.Errorf("session secret")
	}
	return b, nil
}

// ShouldRestart reports whether a device change restarts Xray.
func (c Config) ShouldRestart() bool {
	if c.RestartXray == nil {
		return true
	}
	return *c.RestartXray
}

func validatePublicURL(raw, tlsMode string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("public url")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("public url path")
	}
	switch tlsMode {
	case "off":
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("public url scheme")
		}
	default:
		if u.Scheme != "https" {
			return fmt.Errorf("public url scheme")
		}
	}
	return nil
}

func validHost(s string) bool {
	if s == "" || strings.Contains(s, "://") || strings.ContainsAny(s, "/ \t") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return strings.Contains(s, ".")
}

func randomPassword() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
