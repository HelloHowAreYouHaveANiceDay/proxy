package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/HelloHowAreYouHaveANiceDay/oauthr/cli/internal/sandbox"
)

// runRun implements "oauthr run [--hardened] <command> [args...]".
//
// With --hardened on Windows, the command runs inside a Windows AppContainer
// that denies access to the oauthr token store (%APPDATA%\oauthr\).
// On non-Windows, --hardened is a no-op with a warning.
func runRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	hardened := fs.Bool("hardened", false, "launch <command> in AppContainer sandbox (Windows) or unsandboxed with warning (non-Windows)")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fail("usage", "oauthr run [--hardened] <command> [args...]")
	}

	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if *hardened {
		if err := sandbox.RunInSandbox(cmd); err != nil {
			fail("run", fmt.Sprintf("sandbox: %v", err))
		}
		return
	}

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fail("run", err.Error())
	}
}
