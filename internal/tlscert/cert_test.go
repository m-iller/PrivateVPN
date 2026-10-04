package tlscert

import (
	"crypto/tls"
	"testing"
)

func TestEnsureCreatesCertForIP(t *testing.T) {
	cert, key, err := Ensure(t.TempDir(), "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
	again, _, err := Ensure(filepathDir(t, cert), "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if again != cert {
		t.Fatalf("recreated cert: %s", again)
	}
}

func filepathDir(t *testing.T, cert string) string {
	t.Helper()
	return cert[:len(cert)-len("panel.crt")]
}
