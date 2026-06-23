//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/user"
)

// hardenedUser is the dedicated system account the proxy must run as in --hardened mode.
const hardenedUser = "oauthr-proxy"

// sandboxChildEnv is set in the sandbox child's environment on Windows.
// On Unix --hardened uses a separate uid (not a re-exec); this constant is defined
// here so cross-platform tests that reference it compile on non-Windows.
const sandboxChildEnv = "OAUTHR_SANDBOX_CHILD"

// sandboxLaunch is the Unix sandbox launcher, kept as a variable so tests can
// inject a mock to exercise the fail-closed path without OS privileges.
var sandboxLaunch = unixSandboxNotImplemented

// isHardenedChild reports whether this process is the sandbox child.
// On Unix --hardened does not re-exec, so this is always false in production.
func isHardenedChild() bool {
	return os.Getenv(sandboxChildEnv) == "1"
}

// launchHardenedProxy is the Unix sandbox launcher (delegates to sandboxLaunch).
// On Unix the sandbox is a separate uid, not a re-exec; this always returns an error.
func launchHardenedProxy(exe string, serveArgs []string) error {
	return sandboxLaunch(exe, serveArgs)
}

func unixSandboxNotImplemented(_ string, _ []string) error {
	return fmt.Errorf("--hardened: Unix separate-uid sandbox path not implemented in this release")
}

// hardenedContextOK returns (true, "") when the process is already running as the
// oauthr-proxy system user.  Returns (false, reason) otherwise so the caller can
// fail with a human-readable setup hint.
func hardenedContextOK() (bool, string) {
	u, err := user.Current()
	if err != nil {
		return false, fmt.Sprintf("cannot determine current user: %v", err)
	}
	if u.Username != hardenedUser {
		return false, fmt.Sprintf(
			"--hardened requires the proxy to run as the '%s' system user "+
				"(currently running as '%s').\n"+
				"One-time setup (Linux/macOS):\n"+
				"  sudo useradd --system --no-create-home %s\n"+
				"  sudo chown %s ~/.oauthr/\n"+
				"Then start the proxy as that user:\n"+
				"  sudo -u %s oauthr serve --hardened [flags]",
			hardenedUser, u.Username,
			hardenedUser, hardenedUser, hardenedUser,
		)
	}
	return true, ""
}

// handleHardenedServe validates the Unix --hardened context.
// Fails with setup instructions if not running as the oauthr-proxy system user.
// Always returns false (Unix does not re-exec; the caller continues as the proxy).
func handleHardenedServe(_ string, _ []string) bool {
	if ok, msg := hardenedContextOK(); !ok {
		fail("hardened", msg)
	}
	return false
}
