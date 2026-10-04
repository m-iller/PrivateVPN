package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Ensure returns a self-signed certificate for host, creating it if needed.
func Ensure(dir, host string) (certFile, keyFile string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	certFile = filepath.Join(dir, "panel.crt")
	keyFile = filepath.Join(dir, "panel.key")
	if err := EnsureFiles(certFile, keyFile, host, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// EnsureFiles writes a self-signed certificate for host at the given paths
// with mode perm, unless both files already exist.
func EnsureFiles(certFile, keyFile, host string, perm os.FileMode) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}
	return generate(certFile, keyFile, host, perm)
}

func generate(certFile, keyFile, host string, perm os.FileMode) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, perm); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, perm); err != nil {
		return err
	}
	// WriteFile only applies perm to new files and is masked by umask.
	if err := os.Chmod(certFile, perm); err != nil {
		return err
	}
	return os.Chmod(keyFile, perm)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
