package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestInitWritesSecretsAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	xrayPath := filepath.Join(dir, "xray", "config.json")
	dataDir := filepath.Join(dir, "data")
	err := Init(InitOptions{
		Path:           cfgPath,
		Address:        "203.0.113.10",
		Domain:         "vpn.example.com",
		DataDir:        dataDir,
		XrayConfigPath: xrayPath,
		Password:       "correct-horse",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.password")); !os.IsNotExist(err) {
		t.Fatal("caller-supplied password must not be written to disk")
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.TLSMode != "auto" || cfg.PublicURL != "https://vpn.example.com:8443" {
		t.Fatalf("tls setup: %+v", cfg.PublicURL)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.AdminPasswordHash), []byte("correct-horse")); err != nil {
		t.Fatal(err)
	}
	xb, err := os.ReadFile(xrayPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(xb) == 0 || string(xb[0]) != "{" {
		t.Fatal("xray config missing")
	}
	if err := Init(InitOptions{
		Path:           cfgPath,
		Address:        "203.0.113.10",
		Domain:         "vpn.example.com",
		DataDir:        dataDir,
		XrayConfigPath: xrayPath,
		Password:       "correct-horse",
	}); err == nil {
		t.Fatal("second init should fail")
	}
}

func TestInitGeneratesPasswordFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	err := Init(InitOptions{
		Path:           cfgPath,
		Address:        "203.0.113.10",
		PublicURL:      "https://203.0.113.10:8443",
		DataDir:        filepath.Join(dir, "data"),
		XrayConfigPath: filepath.Join(dir, "xray.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pass, err := os.ReadFile(filepath.Join(dir, "admin.password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSMode != "selfsigned" {
		t.Fatal(cfg.TLSMode)
	}
	pw := string(pass)
	if len(pw) < 10 {
		t.Fatal("short generated password")
	}
	if pw[len(pw)-1] == '\n' {
		pw = pw[:len(pw)-1]
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.AdminPasswordHash), []byte(pw)); err != nil {
		t.Fatal(err)
	}
}
