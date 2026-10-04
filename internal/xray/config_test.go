package xray

import (
	"encoding/json"
	"testing"
)

func testReality(t *testing.T) Reality {
	t.Helper()
	priv, pub, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	return Reality{
		Port:        443,
		Dest:        "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		PrivateKey:  priv,
		PublicKey:   pub,
		ShortIDs:    []string{"0123abcd"},
		Fingerprint: "chrome",
	}
}

func TestBuildIncludesOnlyGivenClients(t *testing.T) {
	r := testReality(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	buf, err := Build(r, nil, []Client{{ID: "11111111-1111-4111-8111-111111111111", Email: "d-1"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Port     int
			Protocol string
			Settings struct {
				Clients []struct {
					ID    string
					Flow  string
					Email string
				}
				Decryption string
			}
			StreamSettings struct {
				Security        string
				RealitySettings struct {
					Dest         string
					ServerNames  []string
					PrivateKey   string
					ShortIds     []string
					MinClientVer string
				}
			}
		}
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatal(err)
	}
	in := doc.Inbounds[0]
	if in.Port != 443 || in.Protocol != "vless" || in.Settings.Decryption != "none" {
		t.Fatalf("inbound: %+v", in)
	}
	if len(in.Settings.Clients) != 1 || in.Settings.Clients[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("clients: %+v", in.Settings.Clients)
	}
	if in.StreamSettings.Security != "reality" || in.StreamSettings.RealitySettings.PrivateKey != r.PrivateKey {
		t.Fatal("reality settings missing")
	}
	if in.StreamSettings.RealitySettings.ShortIds[0] != "0123abcd" {
		t.Fatal("short id")
	}
	if in.StreamSettings.RealitySettings.MinClientVer != "1.0.0" {
		t.Fatal("min client ver")
	}
}

func TestBuildRejectsDuplicateClient(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	_, err := Build(testReality(t), nil, []Client{{ID: id, Email: "a"}, {ID: id, Email: "b"}})
	if err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestBuildCDNUsesXHTTPOverTLS(t *testing.T) {
	cdn := &CDN{
		Host:     "vpn.example.online",
		Port:     443,
		Path:     "/0123456789abcdef",
		CertFile: "/usr/local/etc/xray/cdn.crt",
		KeyFile:  "/usr/local/etc/xray/cdn.key",
	}
	buf, err := Build(testReality(t), cdn, []Client{{ID: "11111111-1111-4111-8111-111111111111", Email: "d-1"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Port     int
			Settings struct {
				Clients []map[string]string
			}
			StreamSettings struct {
				Network     string
				Security    string
				TLSSettings struct {
					Certificates []struct {
						CertificateFile string
						KeyFile         string
					}
				}
				XHTTPSettings struct {
					Path string
					Mode string
				}
				RealitySettings *struct{}
			}
		}
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatal(err)
	}
	in := doc.Inbounds[0]
	ss := in.StreamSettings
	if in.Port != 443 || ss.Network != "xhttp" || ss.Security != "tls" || ss.RealitySettings != nil {
		t.Fatalf("stream: %+v", ss)
	}
	if ss.XHTTPSettings.Path != cdn.Path || ss.XHTTPSettings.Mode != "auto" {
		t.Fatalf("xhttp: %+v", ss.XHTTPSettings)
	}
	if len(ss.TLSSettings.Certificates) != 1 || ss.TLSSettings.Certificates[0].KeyFile != cdn.KeyFile {
		t.Fatalf("tls: %+v", ss.TLSSettings)
	}
	if _, ok := in.Settings.Clients[0]["flow"]; ok {
		t.Fatal("vision flow must not be set on xhttp")
	}
}

func TestCDNValidateRejectsBadPath(t *testing.T) {
	c := CDN{Host: "vpn.example.online", Port: 443, Path: "nopath", CertFile: "a", KeyFile: "b"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected path error")
	}
}

func TestValidateRejectsBadKey(t *testing.T) {
	r := testReality(t)
	r.PrivateKey = "not-a-key"
	if err := r.Validate(); err == nil {
		t.Fatal("expected key error")
	}
}
