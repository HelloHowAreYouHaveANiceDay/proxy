// Command oauthr is the agent-installable credential gateway client: a local
// injecting proxy + CLI + bim-cli driver. See ../SPEC.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		fail("usage", "oauthr <verb> (init|serve|connect|status|whoami|principal|describe|doctor|version|...)")
	}
	switch os.Args[1] {
	case "version":
		emit(map[string]any{"ok": true, "result": map[string]string{"version": version}})
	case "describe":
		emit(map[string]any{"ok": true, "result": describe()})
	case "init":
		runInit(os.Args[2:])
	case "principal":
		if len(os.Args) < 3 {
			fail("usage", "oauthr principal <sub-verb> (token)")
		}
		switch os.Args[2] {
		case "token":
			runPrincipalToken(os.Args[3:])
		default:
			fail("unknown-method", fmt.Sprintf("principal sub-verb %q not implemented (see SPEC.md)", os.Args[2]))
		}
	case "serve":
		runServe(os.Args[2:])
	case "connect":
		runConnect(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "whoami":
		runWhoami()
	case "doctor":
		runDoctor()
	default:
		fail("unknown-method", fmt.Sprintf("verb %q not implemented yet (see SPEC.md)", os.Args[1]))
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 0, "listen port (overrides config, default 8080)")
	principal := fs.String("principal", "", "principal_id (overrides config/env)")
	control := fs.String("control", "", "control plane URL (overrides config/env)")
	secret := fs.String("secret", "", "internal secret (overrides config/env)")
	_ = fs.Parse(args)

	cfg := loadConfig()
	if *port != 0 {
		cfg.Port = *port
	}
	if *principal != "" {
		cfg.PrincipalID = *principal
	}
	if *control != "" {
		cfg.ControlURL = *control
	}
	if *secret != "" {
		cfg.InternalSecret = *secret
	}

	if cfg.ControlURL == "" {
		fail("config", "control URL required: set OAUTHR_CONTROL_URL or --control flag")
	}
	if cfg.PrincipalID == "" {
		fail("config", "principal ID required: set OAUTHR_PRINCIPAL_ID or --principal flag")
	}
	if cfg.InternalSecret == "" {
		fail("config", "internal secret required: set OAUTHR_INTERNAL_SECRET or --secret flag")
	}

	ca, err := loadOrCreateCA(cfg.DataDir)
	if err != nil {
		fail("ca", fmt.Sprintf("failed to load/create CA: %v", err))
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	proxyURL := fmt.Sprintf("http://%s", addr)
	caPath := cfg.DataDir + "/ca.crt"
	p := newProxy(cfg, ca)

	// Write bim-cli instance discovery file; clean up on exit
	if err := writeDiscovery(proxyURL, caPath); err != nil {
		fail("discovery", fmt.Sprintf("failed to write discovery file: %v", err))
	}
	defer removeDiscovery()

	// Print discovery JSON for bim-cli and scripts to parse
	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"proxy": proxyURL,
			"ca":    caPath,
			"pid":   os.Getpid(),
		},
	})

	if err := http.ListenAndServe(addr, p); err != nil {
		fail("serve", err.Error())
	}
}

// describe follows the bim-cli driver protocol. oauthr is a bridge-kind driver:
// it runs a resident injecting proxy and writes an instance-discovery file.
func describe() map[string]any {
	return map[string]any{
		"name":    "oauthr",
		"kind":    "bridge",
		"version": version,
		"verbs":   []string{"init", "principal", "connect", "status", "whoami", "serve", "describe", "doctor", "version"},
		"notes":   []string{"Phase 2: two-tier join tokens (init, principal token). Phase 3: wire/grant/revoke/rotate-key."},
	}
}

func emit(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func fail(kind, msg string) {
	emit(map[string]any{"ok": false, "error": map[string]string{"kind": kind, "message": msg}})
	os.Exit(2)
}
