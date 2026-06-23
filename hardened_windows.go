//go:build windows

// Package main -- Windows --hardened sandbox path.
//
// Isolation primitive: Windows Job Object + CreateRestrictedToken (DISABLE_MAX_PRIVILEGE).
// When the token is a restricted version of the calling process's own primary token,
// CreateProcessAsUser does not require SE_ASSIGNPRIMARYTOKEN_NAME.
// SE_INCREASE_QUOTA_NAME is typically held by interactive sessions; if absent, --hardened
// fails closed with a clear error (no silent unsandboxed fallback).
//
// Cross-boundary contract:
//   - HTTP_PROXY loopback: restricted-token process shares the same network namespace as the
//     caller; 127.0.0.1:PORT is reachable from both sides without any ACL change.
//   - CA trust: the parent writes ca.crt to DataDir before launching the sandbox; the agent
//     reads it via the path in the discovery file, which is unchanged.
//   - Instance discovery: the restricted token retains DACL access to %LOCALAPPDATA% (DACL
//     access, not privilege-based), so the child writes the discovery file normally.
//   - Job Object kill-on-close: the sandbox process dies when the parent process exits.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// sandboxChildEnv is set in the child's environment so the child knows it is already
// running inside the sandbox and skips re-launching.
const sandboxChildEnv = "OAUTHR_SANDBOX_CHILD"

// sandboxLaunch is the function used to create and run the sandboxed proxy child.
// Replaced in tests to simulate sandbox failure (fail-closed path).
var sandboxLaunch = launchWindowsSandbox

func isHardenedChild() bool {
	return os.Getenv(sandboxChildEnv) == "1"
}

func launchHardenedProxy(exe string, serveArgs []string) error {
	return sandboxLaunch(exe, serveArgs)
}

// Windows API constants not in the syscall package.
const (
	disableMaxPrivilege            = 0x00000001 // CreateRestrictedToken DISABLE_MAX_PRIVILEGE
	jobObjectLimitKillOnClose      = 0x00002000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	jobObjectExtendedLimitInfoClass = 9          // JobObjectExtendedLimitInformation (required for KILL_ON_JOB_CLOSE)
	processAllAccess               = 0x001F0FFF
)

// jobiBasicLimitInfo mirrors JOBOBJECT_BASIC_LIMIT_INFORMATION.
// Field types match the Windows SDK: uintptr == SIZE_T/ULONG_PTR on all targets.
// The Go compiler inserts the correct alignment padding automatically (4 bytes after
// LimitFlags and ActiveProcessLimit on 64-bit, none on 32-bit).
type jobiBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// jobiExtendedLimitInfo mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is only valid in this (extended) class.
type jobiExtendedLimitInfo struct {
	BasicLimitInformation jobiBasicLimitInfo
	IoCounters            [6]uint64 // IO_COUNTERS (ReadOp, WriteOp, OtherOp, ReadBytes, WriteBytes, OtherBytes)
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateRestrictedToken    = modAdvapi32.NewProc("CreateRestrictedToken")
	procCreateJobObjectW         = modKernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = modKernel32.NewProc("AssignProcessToJobObject")
	procSetInformationJobObject  = modKernel32.NewProc("SetInformationJobObject")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
)

// launchWindowsSandbox re-executes the proxy binary with a restricted token inside a
// Job Object. Blocks until the child exits and propagates its exit code.
// Returns an error if the sandbox cannot be established -- the caller must fail closed.
func launchWindowsSandbox(exe string, serveArgs []string) error {
	// 1. Open the current process token.
	// syscall.Handle(^uintptr(0)) is the Windows pseudo-handle for the current process
	// (GetCurrentProcess() always returns (HANDLE)-1 = 0xFFFFFFFF).
	var procTok syscall.Token
	if err := syscall.OpenProcessToken(
		syscall.Handle(^uintptr(0)),
		syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY,
		&procTok,
	); err != nil {
		return fmt.Errorf("--hardened: OpenProcessToken: %w", err)
	}
	defer procTok.Close()

	// 2. Create a restricted token from our own primary token.
	// Deriving from the caller's own primary token means CreateProcessAsUser does not
	// require SE_ASSIGNPRIMARYTOKEN_NAME. SE_INCREASE_QUOTA_NAME is still needed and
	// is held by interactive logon sessions on Windows 10/11.
	var restricted syscall.Handle
	r, _, e := procCreateRestrictedToken.Call(
		uintptr(procTok),
		uintptr(disableMaxPrivilege),
		0, 0, // SidsToDisable: none
		0, 0, // PrivilegesToDelete: none
		0, 0, // SidsToRestrict: none
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		return fmt.Errorf("--hardened: CreateRestrictedToken: %w (OS primitive unavailable)", e)
	}
	defer syscall.CloseHandle(restricted)

	// 3. Create a Job Object with kill-on-close: the sandbox dies when the parent exits.
	jobH, _, e := procCreateJobObjectW.Call(0, 0)
	if jobH == 0 {
		return fmt.Errorf("--hardened: CreateJobObject: %w", e)
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
		return fmt.Errorf("--hardened: SetInformationJobObject: %w", e)
	}

	// 4. Launch the sandbox child using the restricted token.
	// Pass the same serve args (including --hardened); the child sees OAUTHR_SANDBOX_CHILD=1
	// and skips re-launching.
	allArgs := append([]string{"serve"}, serveArgs...)
	cmd := exec.Command(exe, allArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), sandboxChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(restricted),
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("--hardened: CreateProcessAsUser (requires SE_INCREASE_QUOTA_NAME -- run elevated for --hardened mode): %w", err)
	}

	// 5. Assign child to the Job Object before it can escape.
	// There is a small window between Start and Assign, but this is acceptable for the
	// threat model (restricting the sandbox process, not preventing escape from inside).
	ph, _, e := procOpenProcess.Call(
		processAllAccess,
		0,
		uintptr(cmd.Process.Pid),
	)
	if ph == 0 {
		_ = cmd.Process.Kill()
		return fmt.Errorf("--hardened: OpenProcess child: %w", e)
	}
	r, _, e = procAssignProcessToJobObject.Call(uintptr(jobObj), ph)
	syscall.CloseHandle(syscall.Handle(ph))
	if r == 0 {
		_ = cmd.Process.Kill()
		return fmt.Errorf("--hardened: AssignProcessToJobObject: %w", e)
	}

	// 6. Wait for child and propagate its exit code.
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return fmt.Errorf("--hardened: proxy exited with error: %w", err)
	}
	return nil
}

// hardenedContextOK is provided for cross-platform test compilation.
// On Windows --hardened uses the Job Object sandbox (handleHardenedServe); this
// function is not called from production code on Windows.
func hardenedContextOK() (bool, string) {
	return false, "--hardened on Windows uses the Job Object + restricted-token sandbox; " +
		"run oauthr serve --hardened (requires SE_INCREASE_QUOTA_NAME, i.e. an elevated session)"
}

// handleHardenedServe re-execs the proxy in a Windows sandbox.
// Returns true if we are the parent (sandbox launched, caller should return).
// Returns false if we are the sandbox child (caller continues serving normally).
func handleHardenedServe(exe string, args []string) bool {
	if isHardenedChild() {
		return false // sandbox child: continue serving normally
	}
	if err := launchHardenedProxy(exe, args); err != nil {
		fail("hardened", fmt.Sprintf("sandbox unavailable (fail-closed, no unsandboxed fallback): %v", err))
	}
	return true // parent: sandbox child exited, parent is done
}

// windowsCmdLine builds a quoted Windows command-line string (used in tests).
func windowsCmdLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteWindowsArg(exe))
	for _, a := range args {
		parts = append(parts, quoteWindowsArg(a))
	}
	return strings.Join(parts, " ")
}

// quoteWindowsArg quotes one argument following Windows ParseArgv/CommandLineToArgvW rules.
func quoteWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, c := range s {
		switch c {
		case '\\':
			slashes++
		case '"':
			for ; slashes > 0; slashes-- {
				b.WriteString(`\\`)
			}
			b.WriteString(`\"`)
		default:
			for ; slashes > 0; slashes-- {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
		}
	}
	for ; slashes > 0; slashes-- {
		b.WriteString(`\\`)
	}
	b.WriteByte('"')
	return b.String()
}
