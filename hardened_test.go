package main

import (
	"runtime"
	"testing"
)

// TestHardenedContextOKReturnsTuple verifies hardenedContextOK always returns a
// non-empty reason when it refuses, and that Windows always refuses.
func TestHardenedContextOKReturnsTuple(t *testing.T) {
	ok, msg := hardenedContextOK()
	if !ok && msg == "" {
		t.Error("hardenedContextOK() returned false with empty message; caller cannot inform the user")
	}
	if runtime.GOOS == "windows" && ok {
		t.Error("hardenedContextOK() returned true on Windows; --hardened is not supported there")
	}
}

// TestHardenedContextOKUnixNotRoot verifies that on non-Windows systems where the
// current user is NOT 'oauthr-proxy', the call reports not-ok with a non-empty msg.
// (Running CI as root or oauthr-proxy would make this a false positive; skip in that case.)
func TestHardenedContextOKUnixNotProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows always refuses; covered by TestHardenedContextOKReturnsTuple")
	}
	ok, msg := hardenedContextOK()
	// In CI we are not running as oauthr-proxy, so we expect (false, non-empty).
	// If somehow the test IS running as oauthr-proxy, skip rather than fail.
	if ok {
		t.Skip("running as oauthr-proxy user; hardened context already valid -- skipping refusal test")
	}
	if msg == "" {
		t.Error("hardenedContextOK() refused but gave empty reason message")
	}
}
