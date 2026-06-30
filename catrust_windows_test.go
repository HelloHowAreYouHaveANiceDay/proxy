//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// makeCAAndLeaf builds a throwaway CA (unique per run) and a leaf cert for 127.0.0.1
// signed by it -- mirroring what the proxy's loadOrCreateCA + leafFor produce.
func makeCAAndLeaf(t *testing.T) (caDER []byte, leaf tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "oauthr test CA (DELETE ME)", Organization: []string{"oauthr-test"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf = tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	return caDER, leaf
}

// TestCATrust_OSVerifierTrustsAfterInstall is the end-to-end proof of the Windows fix:
// after installCACert, a connection presenting a leaf signed by that CA is trusted by the
// DEFAULT http client (RootCAs == nil -> the OS chain verifier, the same path gws.exe uses).
//
// This test MUTATES the CurrentUser Root store and triggers Windows' one-time root-CA
// trust dialog, so it is opt-in: set OAUTHR_TRUST_CA_TEST=1 to run it (a human must click
// "Yes" on the prompt). It is skipped by default so plain `go test ./...` never pops dialogs.
func TestCATrust_OSVerifierTrustsAfterInstall(t *testing.T) {
	if os.Getenv("OAUTHR_TRUST_CA_TEST") != "1" {
		t.Skip("set OAUTHR_TRUST_CA_TEST=1 to run (mutates CurrentUser\\Root; raises the Windows trust dialog)")
	}
	caDER, leaf := makeCAAndLeaf(t)

	if caCertTrusted(caDER) {
		t.Fatal("freshly generated CA should not already be trusted")
	}

	if err := installCACert(caDER); err != nil {
		t.Fatalf("installCACert: %v", err)
	}
	// ALWAYS clean up -- never leave a MITM root CA in the user's store.
	t.Cleanup(func() {
		_ = removeCACert(caDER)
		if caCertTrusted(caDER) {
			t.Errorf("cleanup failed: test CA still present in CurrentUser\\Root")
		}
	})

	if !caCertTrusted(caDER) {
		t.Fatal("caCertTrusted should report true after install")
	}

	// Stand up a TLS server using the leaf; connect with the DEFAULT verifier.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	defer srv.Close()

	// http.DefaultTransport: RootCAs == nil -> Windows OS verifier (gws.exe's path).
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("OS verifier rejected leaf signed by installed CA: %v", err)
	}
	resp.Body.Close()
}
