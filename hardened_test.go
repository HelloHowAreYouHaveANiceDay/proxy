// Tests for the --hardened sandbox path that run on all platforms.
package main

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestHardenedContextOKReturnsTuple verifies hardenedContextOK always returns a
// non-empty reason when it refuses, and that Windows never grants context-OK
// (Windows uses the Job Object sandbox path, not the system-user path).
func TestHardenedContextOKReturnsTuple(t *testing.T) {
	ok, msg := hardenedContextOK()
	if !ok && msg == "" {
		t.Error("hardenedContextOK() returned false with empty message; caller cannot inform the user")
	}
	if runtime.GOOS == "windows" && ok {
		t.Error("hardenedContextOK() returned true on Windows; Windows uses the Job Object sandbox path")
	}
}

// TestHardenedContextOKUnixNotProxy verifies that on non-Windows systems where the
// current user is NOT 'oauthr-proxy', the call reports not-ok with a non-empty msg.
func TestHardenedContextOKUnixNotProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses Job Object sandbox path; covered by TestHardenedContextOKReturnsTuple")
	}
	ok, msg := hardenedContextOK()
	if ok {
		t.Skip("running as oauthr-proxy user; hardened context already valid -- skipping refusal test")
	}
	if msg == "" {
		t.Error("hardenedContextOK() refused but gave empty reason message")
	}
}

// TestHardenedFailClosed verifies that --hardened fails closed when the sandbox
// primitive is unavailable, exercising the sandboxLaunch abstraction used on both
// Windows (production path) and Unix (tests / future re-exec path).
func TestHardenedFailClosed(t *testing.T) {
	orig := sandboxLaunch
	sandboxLaunch = func(_ string, _ []string) error {
		return fmt.Errorf("simulated sandbox-unavailable: CreateRestrictedToken: access denied")
	}
	t.Cleanup(func() { sandboxLaunch = orig })

	err := launchHardenedProxy("oauthr", []string{"--port", "0"})
	if err == nil {
		t.Fatal("launchHardenedProxy returned nil -- unsandboxed fallback occurred (fail-closed violated)")
	}
	if !strings.Contains(err.Error(), "simulated sandbox-unavailable") {
		t.Fatalf("unexpected error (not the injected error): %v", err)
	}
}

// TestHardenedIsChildDetection verifies that isHardenedChild returns the correct
// value based on the OAUTHR_SANDBOX_CHILD environment variable.
func TestHardenedIsChildDetection(t *testing.T) {
	if isHardenedChild() {
		t.Error("isHardenedChild() returned true in the test process (env var not set)")
	}
}
