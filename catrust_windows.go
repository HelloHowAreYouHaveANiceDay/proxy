//go:build windows

// Package main -- Windows CA trust installation.
//
// Why this exists: Go's default TLS verification on Windows (RootCAs == nil) delegates
// to the OS certificate-chain verifier and IGNORES SSL_CERT_FILE. A child process we do
// not control (bim-google's gws.exe) therefore cannot be told to trust the oauthr MITM CA
// via an env var -- the CA must live in the OS trust store. The CurrentUser "Root" store
// is writable by the user WITHOUT administrator rights, so `oauthr trust-ca` installs the
// CA there. We use the low-level crypt32 store API (no new dependency), matching the
// syscall.LazyDLL pattern already used by hardened_windows.go.
//
// NOTE: adding to the CurrentUser Root store raises Windows' one-time "you are about to
// install a certificate from a certification authority" dialog -- a deliberate OS security
// gate for root CAs that cannot be suppressed without elevation/policy. That is the intended
// UX: a single explicit human consent to trust the local MITM CA, equivalent to the one-time
// OAuth `connect` consent click. `oauthr trust-ca` is guarded by caCertTrusted so it prompts
// at most once; `oauthr serve` never installs (it only reads trust state).
package main

import (
	"errors"
	"syscall"
	"unsafe"
)

var errNoCert = errors.New("trust-ca: empty CA certificate")

// trustCAStoreName returns the OS trust-store identifier used by runTrustCA output.
func trustCAStoreName() string { return `CurrentUser\Root` }

var modCrypt32 = syscall.NewLazyDLL("crypt32.dll")

var (
	procCertOpenStore                  = modCrypt32.NewProc("CertOpenStore")
	procCertCloseStore                 = modCrypt32.NewProc("CertCloseStore")
	procCertCreateCertificateContext   = modCrypt32.NewProc("CertCreateCertificateContext")
	procCertAddEncodedCertificateStore = modCrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertFindCertificateInStore     = modCrypt32.NewProc("CertFindCertificateInStore")
	procCertFreeCertificateContext     = modCrypt32.NewProc("CertFreeCertificateContext")
	procCertDeleteCertificateFromStore = modCrypt32.NewProc("CertDeleteCertificateFromStore")
)

const (
	certStoreProvSystemW        = 10
	x509AsnEncoding             = 0x00000001
	pkcs7AsnEncoding            = 0x00010000
	encodingType                = x509AsnEncoding | pkcs7AsnEncoding
	certSystemStoreCurrentUser  = 0x00010000 // 1 << 16
	certStoreAddReplaceExisting = 3
	certCompareExisting         = 13
	certFindExisting            = certCompareExisting << 16 // CERT_FIND_EXISTING
)

// openUserRootStore opens the CurrentUser "Root" certificate store for read/write.
func openUserRootStore() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	h, _, callErr := procCertOpenStore.Call(
		uintptr(certStoreProvSystemW),
		0, // dwEncodingType unused for system stores
		0, // hCryptProv
		uintptr(certSystemStoreCurrentUser),
		uintptr(unsafe.Pointer(name)),
	)
	if h == 0 {
		return 0, callErr
	}
	return h, nil
}

// caCertTrusted reports whether a certificate with these DER bytes is already present
// in the CurrentUser Root store.
func caCertTrusted(der []byte) bool {
	if len(der) == 0 {
		return false
	}
	store, err := openUserRootStore()
	if err != nil {
		return false
	}
	defer procCertCloseStore.Call(store, 0)

	ctx, _, _ := procCertCreateCertificateContext.Call(
		uintptr(encodingType),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
	)
	if ctx == 0 {
		return false
	}
	defer procCertFreeCertificateContext.Call(ctx)

	found, _, _ := procCertFindCertificateInStore.Call(
		store,
		uintptr(encodingType),
		0,
		uintptr(certFindExisting),
		ctx, // pvFindPara = the cert context to match
		0,   // pPrevCertContext
	)
	if found != 0 {
		procCertFreeCertificateContext.Call(found)
		return true
	}
	return false
}

// installCACert adds the CA (DER bytes) to the CurrentUser Root store. Idempotent
// (CERT_STORE_ADD_REPLACE_EXISTING) and needs no admin rights, but raises Windows'
// one-time root-CA trust dialog (see the package comment). Returns nil on success.
func installCACert(der []byte) error {
	if len(der) == 0 {
		return errNoCert
	}
	store, err := openUserRootStore()
	if err != nil {
		return err
	}
	defer procCertCloseStore.Call(store, 0)

	ok, _, callErr := procCertAddEncodedCertificateStore.Call(
		store,
		uintptr(encodingType),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		uintptr(certStoreAddReplaceExisting),
		0, // ppCertContext
	)
	if ok == 0 {
		return callErr
	}
	return nil
}

// removeCACert deletes a certificate with these DER bytes from the CurrentUser Root
// store. No-op if not present. Backs a future `oauthr untrust-ca` and test cleanup.
func removeCACert(der []byte) error {
	if len(der) == 0 {
		return errNoCert
	}
	store, err := openUserRootStore()
	if err != nil {
		return err
	}
	defer procCertCloseStore.Call(store, 0)

	ctx, _, _ := procCertCreateCertificateContext.Call(
		uintptr(encodingType),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
	)
	if ctx == 0 {
		return nil
	}
	defer procCertFreeCertificateContext.Call(ctx)

	found, _, _ := procCertFindCertificateInStore.Call(
		store, uintptr(encodingType), 0, uintptr(certFindExisting), ctx, 0,
	)
	if found == 0 {
		return nil // not present
	}
	// CertDeleteCertificateFromStore frees the passed context on success, so only
	// free it ourselves if the delete fails.
	ok, _, delErr := procCertDeleteCertificateFromStore.Call(found)
	if ok == 0 {
		procCertFreeCertificateContext.Call(found)
		return delErr
	}
	return nil
}
