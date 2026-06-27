//go:build windows

// Package sandbox implements the Windows AppContainer sandbox for the oauthr --hardened path.
//
// Isolation model:
//   - AppContainer profile "oauthr-sandbox" is created once and reused across runs.
//   - The agent command runs inside the container; the oauthr proxy runs outside.
//   - The container SID is not in %APPDATA%\oauthr\'s DACL by default, so tokens.db
//     is inaccessible to the sandboxed process.
//   - Loopback exemption is added (best effort) so the agent can reach the proxy at
//     127.0.0.1. This call requires elevation; it is silently skipped if denied.
//
// API surface used:
//   - userenv.dll: CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName
//   - kernel32.dll: InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
//     DeleteProcThreadAttributeList, CreateProcessW
//   - advapi32.dll: FreeSid
//   - External: CheckNetIsolation.exe (loopback exemption, best effort)
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// ProfileName is the AppContainer profile name used for the oauthr sandbox.
// A multi-tenant deployment would use "oauthr-<tenantId>" per tenant.
const ProfileName = "oauthr-sandbox"

// Windows HRESULT: HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7
const hrAlreadyExists = 0x800700B7

// Process creation flags.
const (
	extendedStartupInfoPresent = 0x00080000 // EXTENDED_STARTUPINFO_PRESENT
	createUnicodeEnvironment   = 0x00000400 // CREATE_UNICODE_ENVIRONMENT
)

// PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES (from processthreadsapi.h).
const procThreadAttrSecurityCapabilities = 0x00020009

// securityCapabilities mirrors SECURITY_CAPABILITIES (securityappcontainer.h).
//
// On 64-bit Windows:
//
//	AppContainerSid *SID: 8 bytes
//	Capabilities    ptr:  8 bytes (nil = no additional capabilities)
//	CapabilityCount u32:  4 bytes
//	Reserved        u32:  4 bytes  (total: 24 bytes)
type securityCapabilities struct {
	AppContainerSid *syscall.SID
	Capabilities    uintptr // *SID_AND_ATTRIBUTES, nil = no capabilities
	CapabilityCount uint32
	Reserved        uint32
}

// startupInfoEx mirrors STARTUPINFOEXW.
// Cb in StartupInfo must be set to unsafe.Sizeof(startupInfoEx{}) so Windows
// reads the AttrList field.
type startupInfoEx struct {
	StartupInfo syscall.StartupInfo
	AttrList    uintptr // LPPROC_THREAD_ATTRIBUTE_LIST
}

var (
	modUserenv  = syscall.NewLazyDLL("userenv.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCreateAppContainerProfile               = modUserenv.NewProc("CreateAppContainerProfile")
	procDeriveAppContainerSidFromAppContainerName = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")

	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW                    = modKernel32.NewProc("CreateProcessW")

	procFreeSid = modAdvapi32.NewProc("FreeSid")
)

// RunInSandbox launches cmd inside a Windows AppContainer sandbox and blocks
// until the child process exits.
//
// The sandboxed process:
//   - Cannot read %APPDATA%\oauthr\ (token isolation by default DACL).
//   - Can reach 127.0.0.1 (loopback exemption added best effort).
//   - Inherits stdin/stdout/stderr from the parent.
//
// On non-zero child exit code this function calls os.Exit with the same code.
// Returns an error only if the sandbox cannot be established (fail-closed).
func RunInSandbox(cmd *exec.Cmd) error {
	sid, err := ensureProfile(ProfileName)
	if err != nil {
		return fmt.Errorf("AppContainer profile: %w", err)
	}
	defer procFreeSid.Call(uintptr(unsafe.Pointer(sid)))

	// Loopback exemption: allows the container to reach 127.0.0.1 (the proxy).
	// Requires elevation; silently ignored if denied.
	addLoopbackExemption(ProfileName)

	sc := securityCapabilities{
		AppContainerSid: sid,
		Capabilities:    0,
		CapabilityCount: 0,
	}
	attrBuf, err := buildAttrList(&sc)
	if err != nil {
		return fmt.Errorf("AppContainer attr list: %w", err)
	}
	attrPtr := uintptr(unsafe.Pointer(&attrBuf[0]))

	err = launchInContainer(cmd, attrPtr)
	procDeleteProcThreadAttributeList.Call(attrPtr)
	runtime.KeepAlive(attrBuf)
	runtime.KeepAlive(sc)
	return err
}

// ensureProfile returns the AppContainer SID for name, creating the profile if
// it does not already exist. The caller must free the returned SID with FreeSid.
func ensureProfile(name string) (*syscall.SID, error) {
	namep, _ := syscall.UTF16PtrFromString(name)
	displayp, _ := syscall.UTF16PtrFromString("oauthr agent sandbox")
	descp, _ := syscall.UTF16PtrFromString("oauthr --hardened AppContainer isolation")

	var sid *syscall.SID
	hr, _, _ := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namep)),
		uintptr(unsafe.Pointer(displayp)),
		uintptr(unsafe.Pointer(descp)),
		0, 0, // no additional capabilities
		uintptr(unsafe.Pointer(&sid)),
	)
	if uint32(hr) == hrAlreadyExists {
		hr2, _, e := procDeriveAppContainerSidFromAppContainerName.Call(
			uintptr(unsafe.Pointer(namep)),
			uintptr(unsafe.Pointer(&sid)),
		)
		if hr2 != 0 {
			return nil, fmt.Errorf("DeriveAppContainerSidFromAppContainerName: HRESULT=0x%08X: %w", uint32(hr2), e)
		}
	} else if hr != 0 {
		return nil, fmt.Errorf("CreateAppContainerProfile: HRESULT=0x%08X", uint32(hr))
	}
	return sid, nil
}

// addLoopbackExemption calls CheckNetIsolation to exempt the AppContainer from
// loopback restrictions. This is required for the sandboxed agent to reach the
// oauthr proxy at 127.0.0.1. Requires elevation; failure is silently ignored.
func addLoopbackExemption(name string) {
	_ = exec.Command("CheckNetIsolation.exe", "LoopbackExempt", "-a", "-n="+name).Run()
}

// buildAttrList allocates a PROC_THREAD_ATTRIBUTE_LIST containing the
// SECURITY_CAPABILITIES for the AppContainer. The caller must call
// DeleteProcThreadAttributeList on the returned buffer's first element and
// keep the buffer alive until after any CreateProcess call that uses it.
func buildAttrList(sc *securityCapabilities) ([]byte, error) {
	// Query required size (first call is expected to return FALSE / ERROR_INSUFFICIENT_BUFFER).
	var size uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 512 // conservative fallback
	}
	buf := make([]byte, size)
	r, _, e := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		1, // dwAttributeCount
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", e)
	}
	r, _, e = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		0,
		procThreadAttrSecurityCapabilities,
		uintptr(unsafe.Pointer(sc)),
		unsafe.Sizeof(*sc),
		0, 0,
	)
	if r == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %w", e)
	}
	return buf, nil
}

// launchInContainer calls CreateProcessW with EXTENDED_STARTUPINFO_PRESENT and
// the given PROC_THREAD_ATTRIBUTE_LIST, blocks until the child exits, and
// calls os.Exit if the child exits non-zero.
func launchInContainer(cmd *exec.Cmd, attrList uintptr) error {
	siEx := startupInfoEx{}
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.AttrList = attrList
	// Standard handles are inherited from the parent (no STARTF_USESTDHANDLES needed).

	cmdLine := buildCmdLine(cmd.Path, cmd.Args)
	cmdLinep, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return fmt.Errorf("command line UTF-16: %w", err)
	}

	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	envBlock := buildEnvBlock(env)

	var dirp *uint16
	if cmd.Dir != "" {
		dirp, err = syscall.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			return fmt.Errorf("working dir UTF-16: %w", err)
		}
	}

	var pi syscall.ProcessInformation
	r, _, e := procCreateProcessW.Call(
		0, // lpApplicationName: derive from command line
		uintptr(unsafe.Pointer(cmdLinep)),
		0, 0, // process/thread security attrs: inherit parent DACL
		1, // bInheritHandles: TRUE -- child inherits stdin/stdout/stderr
		uintptr(extendedStartupInfoPresent|createUnicodeEnvironment),
		uintptr(unsafe.Pointer(&envBlock[0])),
		uintptr(unsafe.Pointer(dirp)),
		uintptr(unsafe.Pointer(&siEx)), // cast: STARTUPINFOEX* -> LPSTARTUPINFO
		uintptr(unsafe.Pointer(&pi)),
	)
	runtime.KeepAlive(cmdLinep)
	runtime.KeepAlive(envBlock)
	runtime.KeepAlive(dirp)
	if r == 0 {
		return fmt.Errorf("CreateProcess (AppContainer): %w", e)
	}
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)

	if _, err := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE); err != nil {
		return fmt.Errorf("WaitForSingleObject: %w", err)
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(pi.Process, &code); err != nil {
		return fmt.Errorf("GetExitCodeProcess: %w", err)
	}
	if code != 0 {
		os.Exit(int(code))
	}
	return nil
}

// buildEnvBlock converts a []string of "KEY=VALUE" pairs into the UTF-16
// double-null-terminated block expected by CreateProcessW with CREATE_UNICODE_ENVIRONMENT.
func buildEnvBlock(env []string) []uint16 {
	var block []uint16
	for _, e := range env {
		u16, _ := syscall.UTF16FromString(e) // includes null terminator
		block = append(block, u16...)
	}
	block = append(block, 0) // final double-null (UTF16FromString already added one per string)
	return block
}

// buildCmdLine constructs a Windows command-line string from exe and args.
// args[0] is expected to be the program name and is skipped (exe is used instead).
func buildCmdLine(exe string, args []string) string {
	parts := make([]string, 0, len(args))
	parts = append(parts, quoteArg(exe))
	if len(args) > 1 {
		for _, a := range args[1:] {
			parts = append(parts, quoteArg(a))
		}
	}
	return strings.Join(parts, " ")
}

// quoteArg quotes a single argument following Windows CommandLineToArgvW rules.
func quoteArg(s string) string {
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
