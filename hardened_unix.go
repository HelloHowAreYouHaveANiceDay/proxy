//go:build !windows

package main

import (
	"fmt"
	"os/user"
)

// hardenedUser is the dedicated system account the proxy must run as in --hardened mode.
const hardenedUser = "oauthr-proxy"

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
