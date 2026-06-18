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

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		fail("usage", "oauthr <verb> (serve|describe|doctor|version|...)")
	}
	switch os.Args[1] {
	case "version":
		emit(map[string]any{"ok": true, "result": map[string]string{"version": version}})
	case "describe":
		emit(map[string]any{"ok": true, "result": describe()})
	case "doctor":
		emit(map[string]any{"ok": true, "result": map[string]any{"version": version, "checks": []any{}}})
	case "serve":
		runServe(os.Args[2:])
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
	p := newProxy(cfg, ca)

	// Print discovery JSON for bim-cli and scripts to parse
	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"proxy": fmt.Sprintf("http://%s", addr),
			"ca":    cfg.DataDir + "/ca.crt",
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
		"verbs":   []string{"init", "wire", "connect", "status", "describe", "doctor", "revoke", "rotate-key", "whoami", "serve", "grant"},
		"notes":   []string{"Phase 1 skeleton — verbs not yet implemented. See SPEC.md."},
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
