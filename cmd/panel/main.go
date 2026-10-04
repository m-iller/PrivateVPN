package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"privatevpn/internal/config"
	"privatevpn/internal/httpapi"
	"privatevpn/internal/session"
	"privatevpn/internal/store"
	"privatevpn/internal/tlscert"
	"privatevpn/internal/xray"
)

func main() {
	log.SetFlags(0)
	fs := flag.NewFlagSet("privatevpn", flag.ExitOnError)
	configPath := fs.String("config", "/etc/privatevpn/config.json", "config file")
	initMode := fs.Bool("init", false, "write a new config and exit")
	address := fs.String("address", "", "public IP or hostname clients connect to")
	domain := fs.String("domain", "", "panel domain for Let's Encrypt")
	cdnHost := fs.String("cdn", "", "Cloudflare proxied hostname; serves VLESS over XHTTP+TLS instead of Reality")
	publicURL := fs.String("public-url", "", "https URL of the panel, no path")
	dataDir := fs.String("data-dir", "/var/lib/privatevpn", "state directory")
	xrayPath := fs.String("xray-config", "/usr/local/etc/xray/config.json", "xray config path")
	listen := fs.String("listen", ":8443", "panel listen address")
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	if *initMode {
		if err := config.Init(config.InitOptions{
			Path:           *configPath,
			Address:        *address,
			Domain:         *domain,
			CDNHost:        *cdnHost,
			PublicURL:      *publicURL,
			DataDir:        *dataDir,
			XrayConfigPath: *xrayPath,
			Listen:         *listen,
			Password:       os.Getenv("ADMIN_PASSWORD"),
		}); err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote %s", *configPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	if err := cfg.EnsureCDNCert(); err != nil {
		log.Fatal(err)
	}
	secret, err := cfg.SessionKey()
	if err != nil {
		log.Fatal(err)
	}
	devices, err := store.Open(filepath.Join(cfg.DataDir, "devices.json"))
	if err != nil {
		log.Fatal(err)
	}
	sync := func() error { return syncXray(cfg, devices) }
	if err := sync(); err != nil {
		log.Fatal(err)
	}

	secureCookie := strings.HasPrefix(cfg.PublicURL, "https://")
	api := &httpapi.Server{
		Store:        devices,
		PublicURL:    cfg.PublicURL,
		Address:      cfg.ServerAddress,
		Reality:      cfg.Reality,
		CDN:          cfg.CDN,
		PasswordHash: []byte(cfg.AdminPasswordHash),
		Sessions:     session.New(secret, secureCookie),
		Sync:         sync,
		MaxDevices:   cfg.MaxDevices,
		LoginLimit:   &httpapi.Limiter{Limit: 8, Window: 15 * time.Minute},
		SubLimit:     &httpapi.Limiter{Limit: 60, Window: time.Minute},
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, srv, cfg)
	}()

	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func serve(ctx context.Context, srv *http.Server, cfg config.Config) error {
	log.Printf("panel listening on %s (%s)", cfg.Listen, cfg.TLSMode)
	switch cfg.TLSMode {
	case "off":
		return srv.ListenAndServe()
	case "selfsigned":
		cert, key, err := tlscert.Ensure(cfg.DataDir, cfg.ServerAddress)
		if err != nil {
			return err
		}
		return srv.ListenAndServeTLS(cert, key)
	case "auto":
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "certs")),
		}
		plain := &http.Server{
			Addr:              ":80",
			Handler:           mgr.HTTPHandler(nil),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
		go func() {
			<-ctx.Done()
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = plain.Shutdown(shut)
		}()
		go func() {
			if err := plain.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("acme http: %v", err)
			}
		}()
		srv.TLSConfig = mgr.TLSConfig()
		srv.TLSConfig.MinVersion = tls.VersionTLS12
		return srv.ListenAndServeTLS("", "")
	default:
		return fmt.Errorf("tls mode %q", cfg.TLSMode)
	}
}

func syncXray(cfg config.Config, devices *store.Store) error {
	active, err := devices.Active()
	if err != nil {
		return err
	}
	clients := make([]xray.Client, 0, len(active))
	for _, d := range active {
		clients = append(clients, xray.Client{ID: d.UUID, Email: fmt.Sprintf("d-%d", d.ID)})
	}
	if err := xray.WriteFile(cfg.XrayConfigPath, cfg.Reality, cfg.CDN, clients); err != nil {
		return err
	}
	if !cfg.ShouldRestart() {
		return nil
	}
	cmd := exec.Command("/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", "xray")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("restart xray: %w: %s", err, msg)
	}
	return nil
}
