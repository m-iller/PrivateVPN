package sub

import (
	"strings"
	"testing"

	"privatevpn/internal/xray"
)

func TestBodyIsRefreshableVLESS(t *testing.T) {
	priv, pub, err := xray.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	uuid := "11111111-1111-4111-8111-111111111111"
	body, err := (Link{
		Name:    "Phone",
		UUID:    uuid,
		Address: "203.0.113.10",
		Reality: xray.Reality{
			Port:        443,
			Dest:        "www.microsoft.com:443",
			ServerNames: []string{"www.microsoft.com"},
			PrivateKey:  priv,
			PublicKey:   pub,
			ShortIDs:    []string{"0123abcd"},
			Fingerprint: "chrome",
		},
	}).Body()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{
		"#subscription-always-hwid-enable: 1",
		"#profile-update-interval: 12",
		"#profile-title: Phone",
		"vless://" + uuid + "@203.0.113.10:443",
		"encryption=none",
		"flow=xtls-rprx-vision",
		"security=reality",
		"sni=www.microsoft.com",
		"fp=chrome",
		"pbk=" + pub,
		"sid=0123abcd",
		"type=tcp",
	} {
		if !strings.Contains(body, part) {
			t.Fatalf("missing %s in %s", part, body)
		}
	}
	if strings.Contains(body, priv) {
		t.Fatal("subscription leaked the reality private key")
	}
}

func TestSubscriptionURL(t *testing.T) {
	got := URL("https://vpn.example.com:8443/", "abc")
	if got != "https://vpn.example.com:8443/s/abc" {
		t.Fatal(got)
	}
}
