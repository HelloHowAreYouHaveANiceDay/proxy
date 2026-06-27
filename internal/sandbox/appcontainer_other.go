//go:build !windows

// Package sandbox provides the --hardened sandbox launcher.
// On non-Windows platforms, AppContainer is unavailable; RunInSandbox runs the
// command unsandboxed with a warning so cross-platform builds still compile.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// ProfileName is the AppContainer profile name (unused on non-Windows).
const ProfileName = "oauthr-sandbox"

// RunInSandbox runs cmd without sandboxing on non-Windows platforms.
// AppContainer is Windows-only; --hardened is a no-op here.
func RunInSandbox(cmd *exec.Cmd) error {
	fmt.Fprintln(os.Stderr, "warning: AppContainer sandbox is Windows-only; --hardened ignored")
	return cmd.Run()
}
