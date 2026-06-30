//go:build !windows

// Package main -- non-Windows CA trust.
//
// On Unix/macOS, Go honors SSL_CERT_FILE / SSL_CERT_DIR in the default TLS verification
// path, and the proxy hands child processes the CA via SSL_CERT_FILE; drivers that make
// calls in-process use an explicit RootCAs pool. So no OS trust-store mutation is needed:
// installCACert is a no-op and caCertTrusted reports true iff the CA cert has been created.
package main

// caCertTrusted reports true when the CA cert exists (non-empty DER), meaning the proxy
// can make it available to child processes via SSL_CERT_FILE. Returns false if the CA has
// not been generated yet, so discovery files do not advertise ca_trusted prematurely.
func caCertTrusted(der []byte) bool { return len(der) > 0 }

// trustCAStoreName returns the OS trust-store identifier used by runTrustCA output.
// On non-Windows, trust is achieved via SSL_CERT_FILE rather than an OS store.
func trustCAStoreName() string { return "n/a" }

// installCACert is a no-op off Windows. The proxy passes the CA path to children via
// SSL_CERT_FILE; there is nothing to install into an OS store.
func installCACert(der []byte) error { return nil }

// removeCACert is a no-op off Windows (nothing was installed into an OS store).
func removeCACert(der []byte) error { return nil }
