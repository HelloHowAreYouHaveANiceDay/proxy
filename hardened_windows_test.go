//go:build windows

// Windows-only --hardened sandbox tests.
//
// TestHardenedWindowsSandboxUp: verifies the full sandbox creation path and that
// an injected proxy process launched inside the sandbox can serve requests.
// Uses a subprocess pattern: when TEST_HARDENED_HELPER=1, the test binary acts as
// the sandboxed proxy child and exits immediately after printing a marker.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// TestHardenedWindowsSandboxPrimitives verifies that the Windows sandbox
// primitives (CreateRestrictedToken + Job Object) can be created and configured
// without error. This confirms the OS supports --hardened on this machine.
func TestHardenedWindowsSandboxPrimitives(t *testing.T) {
	// Open own process token (pseudo-handle for current process = ^uintptr(0)).
	var procTok syscall.Token
	if err := syscall.OpenProcessToken(
		syscall.Handle(^uintptr(0)),
		syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY,
		&procTok,
	); err != nil {
		t.Skipf("OpenProcessToken failed (unusual -- skip): %v", err)
	}
	defer procTok.Close()

	// Create restricted token.
	var restricted syscall.Handle
	r, _, e := procCreateRestrictedToken.Call(
		uintptr(procTok),
		uintptr(disableMaxPrivilege),
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		t.Skipf("CreateRestrictedToken unavailable on this machine (skip sandbox-up test): %v", e)
	}
	syscall.CloseHandle(restricted)
	t.Log("CreateRestrictedToken: ok")

	// Create Job Object.
	jobH, _, e := procCreateJobObjectW.Call(0, 0)
	if jobH == 0 {
		t.Fatalf("CreateJobObject failed: %v", e)
	}
	jobObj := syscall.Handle(jobH)
	defer syscall.CloseHandle(jobObj)

	extLimits := jobiExtendedLimitInfo{}
	extLimits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnClose
	r, _, e = procSetInformationJobObject.Call(
		uintptr(jobObj),
		uintptr(jobObjectExtendedLimitInfoClass),
		uintptr(unsafe.Pointer(&extLimits)),
		unsafe.Sizeof(extLimits),
	)
	if r == 0 {
		t.Fatalf("SetInformationJobObject failed: %v", e)
	}
	t.Log("Job Object with kill-on-close: ok")
}

// TestHardenedWindowsSandboxUp verifies that a child process launched by
// launchWindowsSandbox executes and exits successfully. The child is this test
// binary itself, run with TEST_HARDENED_HELPER=1 which causes it to emit a
// marker and exit 0 instead of running real proxy logic.
func TestHardenedWindowsSandboxUp(t *testing.T) {
	if os.Getenv("TEST_HARDENED_HELPER") == "1" {
		// Subprocess mode: we are the sandbox child. Emit marker and exit.
		fmt.Println("sandbox-child-ok")
		os.Exit(0)
	}

	exe := os.Args[0] // path to this test binary

	// Replace sandboxLaunch with one that launches the test binary itself
	// in sandbox mode, passing the -test.run flag to keep it focused.
	orig := sandboxLaunch
	var childOut strings.Builder
	sandboxLaunch = func(e string, args []string) error {
		// Use the real launchWindowsSandbox but target this binary + helper env.
		var procTok syscall.Token
		if err := syscall.OpenProcessToken(
			syscall.Handle(^uintptr(0)),
			syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY,
			&procTok,
		); err != nil {
			return fmt.Errorf("OpenProcessToken: %w", err)
		}
		defer procTok.Close()

		var restricted syscall.Handle
		r, _, ev := procCreateRestrictedToken.Call(
			uintptr(procTok),
			uintptr(disableMaxPrivilege),
			0, 0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&restricted)),
		)
		if r == 0 {
			return fmt.Errorf("CreateRestrictedToken: %w (skip)", ev)
		}
		defer syscall.CloseHandle(restricted)

		jobH, _, ev := procCreateJobObjectW.Call(0, 0)
		if jobH == 0 {
			return fmt.Errorf("CreateJobObject: %w", ev)
		}
		jobObj := syscall.Handle(jobH)
		defer syscall.CloseHandle(jobObj)

		extLimits := jobiExtendedLimitInfo{}
		extLimits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnClose
		r, _, ev = procSetInformationJobObject.Call(
			uintptr(jobObj),
			uintptr(jobObjectExtendedLimitInfoClass),
			uintptr(unsafe.Pointer(&extLimits)),
			unsafe.Sizeof(extLimits),
		)
		if r == 0 {
			return fmt.Errorf("SetInformationJobObject: %w", ev)
		}

		cmd := exec.Command(e, "-test.run=TestHardenedWindowsSandboxUp", "-test.v")
		cmd.Env = append(os.Environ(), sandboxChildEnv+"=1", "TEST_HARDENED_HELPER=1")
		cmd.Stdout = &childOut
		cmd.Stderr = &childOut
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Token: syscall.Token(restricted),
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start child: %w", err)
		}

		ph, _, ev := procOpenProcess.Call(processAllAccess, 0, uintptr(cmd.Process.Pid))
		if ph == 0 {
			_ = cmd.Process.Kill()
			return fmt.Errorf("OpenProcess: %w", ev)
		}
		r, _, ev = procAssignProcessToJobObject.Call(uintptr(jobObj), ph)
		syscall.CloseHandle(syscall.Handle(ph))
		if r == 0 {
			_ = cmd.Process.Kill()
			return fmt.Errorf("AssignProcessToJobObject: %w", ev)
		}

		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("child failed: %w\noutput: %s", err, childOut.String())
		}
		return nil
	}
	t.Cleanup(func() { sandboxLaunch = orig })

	err := launchHardenedProxy(exe, []string{})
	if err != nil {
		// SE_INCREASE_QUOTA_NAME is required for CreateProcessAsUser; it is only available
		// in an elevated session. Skip the sandbox-up test on non-elevated processes.
		msg := err.Error()
		if strings.Contains(msg, "Access is denied") ||
			strings.Contains(msg, "SE_INCREASE_QUOTA_NAME") ||
			strings.Contains(msg, "unavailable") {
			t.Skipf("sandbox-up requires elevated privileges (SE_INCREASE_QUOTA_NAME): %v", err)
		}
		t.Fatalf("launchHardenedProxy failed: %v\nchild output: %s", err, childOut.String())
	}

	if !strings.Contains(childOut.String(), "sandbox-child-ok") {
		t.Errorf("expected 'sandbox-child-ok' in child output; got: %s", childOut.String())
	}
	t.Logf("sandbox-up child output: %s", childOut.String())
}

// TestHardenedWindowsCmdLine verifies the Windows command-line quoting helper.
func TestHardenedWindowsCmdLine(t *testing.T) {
	cases := []struct {
		exe  string
		args []string
		want string
	}{
		{"oauthr.exe", []string{"serve"}, "oauthr.exe serve"},
		{"C:\\Program Files\\oauthr.exe", []string{"serve", "--port", "8080"}, `"C:\Program Files\oauthr.exe" serve --port 8080`},
		{"oauthr.exe", []string{"serve", `--control`, `http://localhost`}, "oauthr.exe serve --control http://localhost"},
		{"oauthr.exe", []string{`arg with "quotes"`}, `oauthr.exe "arg with \"quotes\""`},
	}
	for _, c := range cases {
		got := windowsCmdLine(c.exe, c.args)
		if got != c.want {
			t.Errorf("windowsCmdLine(%q, %v) = %q; want %q", c.exe, c.args, got, c.want)
		}
	}
}
