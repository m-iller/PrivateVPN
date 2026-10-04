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
	buf, err := Build(r, []Client{{ID: "11111111-1111-4111-8111-111111111111", Email: "d-1"}})
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
					Dest        string
					ServerNames []string
					PrivateKey  string
					ShortIds    []string
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
}

func TestBuildRejectsDuplicateClient(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	_, err := Build(testReality(t), []Client{{ID: id, Email: "a"}, {ID: id, Email: "b"}})
	if err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestValidateRejectsBadKey(t *testing.T) {
	r := testReality(t)
	r.PrivateKey = "not-a-key"
	if err := r.Validate(); err == nil {
		t.Fatal("expected key error")
	}
}
