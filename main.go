// Command oauthr is the agent-installable credential gateway client: a local
// injecting proxy + CLI + bim-cli driver. Phase 1 skeleton — see ../SPEC.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const version = "0.0.0"

func main() {
	if len(os.Args) < 2 {
		fail("usage", "oauthr <verb> (describe|doctor|version|...)")
	}
	switch os.Args[1] {
	case "version":
		emit(map[string]any{"ok": true, "result": map[string]string{"version": version}})
	case "describe":
		emit(map[string]any{"ok": true, "result": describe()})
	case "doctor":
		emit(map[string]any{"ok": true, "result": map[string]any{"version": version, "checks": []any{}}})
	default:
		fail("unknown-method", fmt.Sprintf("verb %q not implemented in the Phase 1 skeleton (see SPEC.md)", os.Args[1]))
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
