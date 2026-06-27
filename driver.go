package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// discoveryDir returns the bim-cli instances directory for discovery files.
func discoveryDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "bim-cli", "instances")
}

// discoveryPath returns the path for this process's discovery file.
func discoveryPath() string {
	return filepath.Join(discoveryDir(), fmt.Sprintf("oauthr-%d.json", os.Getpid()))
}

// DiscoveryEntry is written to the instances directory when the proxy starts.
type DiscoveryEntry struct {
	Driver string `json:"driver"`
	PID    int    `json:"pid"`
	Proxy  string `json:"proxy"`
	CA     string `json:"ca"`
}

// writeDiscovery writes (or overwrites) the instance discovery file.
// caPath is the filesystem path to the MITM CA; its PEM contents are inlined
// into the discovery file's "ca" field (the documented contract -- consumers
// like the bim-linear driver build an x509 pool directly from this field, not
// from a path).
func writeDiscovery(proxy, caPath string) error {
	dir := discoveryDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	caPEM := ""
	if caPath != "" {
		b, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("read CA for discovery file: %w", err)
		}
		caPEM = string(b)
	}
	e := DiscoveryEntry{
		// The proxy is generic -- it injects for every registered service
		// (google, linear, ...), so it advertises an empty driver. Cloud-driver
		// discovery accepts an instance whose driver is "" (generic) or matches
		// its own service; advertising a single name (e.g. "oauthr") would make
		// every service driver skip this proxy.
		Driver: "",
		PID:    os.Getpid(),
		Proxy:  proxy,
		CA:     caPEM,
	}
	b, _ := json.Marshal(e)
	return os.WriteFile(discoveryPath(), b, 0644)
}

// removeDiscovery deletes the instance discovery file for this process.
func removeDiscovery() {
	_ = os.Remove(discoveryPath())
}

// findLiveProxy returns the proxy URL of a running oauthr instance, or "".
func findLiveProxy() string {
	dir := discoveryDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "oauthr-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var d DiscoveryEntry
		if err := json.Unmarshal(b, &d); err != nil || d.Proxy == "" {
			continue
		}
		// Verify the proxy is actually alive
		resp, err := http.Get(d.Proxy + "/healthz") //nolint:gosec
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return d.Proxy
		}
		// Stale file — clean up
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return ""
}

// runConnect implements `oauthr connect <service> [--label <label>]`.
// It starts an OAuth PKCE session, prints the consent URL, and polls until connected.
func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	label := fs.String("label", "default", "credential slot label")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fail("usage", "oauthr connect <service> [--label <label>]")
	}
	service := fs.Arg(0)

	cfg := loadConfig()
	if cfg.ControlURL == "" {
		fail("config", "OAUTHR_CONTROL_URL not set")
	}
	if cfg.PrincipalID == "" {
		fail("config", "OAUTHR_PRINCIPAL_ID not set")
	}

	// POST /v1/auth/sessions — start PKCE connect flow
	body, _ := json.Marshal(map[string]string{
		"principal_id": cfg.PrincipalID,
		"service":      service,
		"label":        *label,
		"redirect_uri": cfg.ControlURL + "/v1/auth/callback",
	})
	resp, err := http.Post(cfg.ControlURL+"/v1/auth/sessions", "application/json", strings.NewReader(string(body))) //nolint:gosec
	if err != nil {
		fail("network", fmt.Sprintf("POST /v1/auth/sessions: %v", err))
	}
	defer resp.Body.Close()

	var sr struct {
		OK     bool `json:"ok"`
		Result struct {
			SessionID string `json:"session_id"`
			AuthURL   string `json:"auth_url"`
		} `json:"result"`
		Error struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		fail("parse", fmt.Sprintf("unexpected response from /v1/auth/sessions: %v", err))
	}
	if !sr.OK {
		fail(sr.Error.Kind, sr.Error.Message)
	}

	// Surface consent URL to the caller (human or orchestrator)
	fmt.Fprintf(os.Stderr, "Open this URL in your browser to authorize %s:\n\n  %s\n\nWaiting for authorization...\n", service, sr.Result.AuthURL)
	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"status":     "pending",
			"consent_url": sr.Result.AuthURL,
			"session_id": sr.Result.SessionID,
		},
	})

	// Poll GET /v1/auth/sessions/:id until used or timeout
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)

		pollResp, err := http.Get(cfg.ControlURL + "/v1/auth/sessions/" + sr.Result.SessionID) //nolint:gosec
		if err != nil {
			continue
		}
		var ps struct {
			OK     bool `json:"ok"`
			Result struct {
				Used bool `json:"used"`
			} `json:"result"`
		}
		_ = json.NewDecoder(pollResp.Body).Decode(&ps)
		pollResp.Body.Close()

		if ps.OK && ps.Result.Used {
			emit(map[string]any{
				"ok": true,
				"result": map[string]any{
					"status":  "connected",
					"service": service,
					"label":   *label,
				},
			})
			return
		}
	}
	fail("timeout", "authorization not completed within 10 minutes")
}

// runStatus implements `oauthr status [<service>] [--label <label>]`.
func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	label := fs.String("label", "default", "credential slot label")
	_ = fs.Parse(args)

	cfg := loadConfig()
	if cfg.ControlURL == "" {
		fail("config", "OAUTHR_CONTROL_URL not set")
	}
	if cfg.PrincipalID == "" && cfg.ProxyToken == "" {
		fail("config", "not enrolled: run `oauthr init` for a proxy_token, or set OAUTHR_PRINCIPAL_ID")
	}

	service := ""
	if fs.NArg() > 0 {
		service = fs.Arg(0)
	}
	if service == "" {
		service = "google"
	}

	if cfg.ProxyToken == "" && cfg.InternalSecret == "" {
		fail("config", "no control-plane credential: run `oauthr init` for a proxy_token, or set OAUTHR_INTERNAL_SECRET")
	}

	// A successful token mint proves the credential is present and refreshable.
	res, err := fetchToken(cfg, service, *label)
	if err != nil {
		os.Exit(3) // exit code 3 = not-connected (SPEC §11)
	}
	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"status":       "connected",
			"service":      service,
			"label":        *label,
			"principal_id": cfg.PrincipalID,
			"expires_at":   res.ExpiresAt,
		},
	})
}

// runWhoami implements `oauthr whoami`.
func runWhoami() {
	cfg := loadConfig()
	if cfg.AgentID == "" && cfg.PrincipalID == "" {
		fail("not-enrolled", "not enrolled; run `oauthr init` first")
	}
	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"agent_id":     cfg.AgentID,
			"principal_id": cfg.PrincipalID,
			"control_url":  cfg.ControlURL,
		},
	})
}

// runDoctor implements `oauthr doctor`.
func runDoctor() {
	cfg := loadConfig()
	checks := []map[string]any{}

	checks = append(checks, checkField("control_url", cfg.ControlURL != "", "set OAUTHR_CONTROL_URL or add control_url to ~/.oauthr/config.json"))
	// Capability-first: a proxy_token authenticates and scopes on its own. The
	// principal_id + internal-secret pair is the legacy fallback. The broker is
	// healthy if either credential is present.
	hasCapability := cfg.ProxyToken != "" || (cfg.PrincipalID != "" && cfg.InternalSecret != "")
	checks = append(checks, checkField("credential", hasCapability, "run `oauthr init` to enroll (proxy_token), or set OAUTHR_PRINCIPAL_ID + OAUTHR_INTERNAL_SECRET"))

	// Reachability
	if cfg.ControlURL != "" {
		resp, err := http.Get(cfg.ControlURL + "/healthz") //nolint:gosec
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			checks = append(checks, check("control_plane_reachable", true, ""))
		} else {
			msg := "GET /healthz failed"
			if err != nil {
				msg = err.Error()
			}
			checks = append(checks, check("control_plane_reachable", false, msg))
		}
	}

	// CA file
	home, _ := os.UserHomeDir()
	caPath := filepath.Join(home, ".oauthr", "ca.crt")
	_, caErr := os.Stat(caPath)
	checks = append(checks, check("ca_cert_present", caErr == nil, "run `oauthr serve` once to generate the CA"))

	// Live proxy
	proxyURL := findLiveProxy()
	checks = append(checks, check("proxy_running", proxyURL != "", "run `oauthr serve` or call a driver verb to auto-start"))

	allOK := true
	for _, c := range checks {
		if c["ok"] == false {
			allOK = false
			break
		}
	}

	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"version": version,
			"healthy": allOK,
			"checks":  checks,
		},
	})
}

func checkField(name string, ok bool, hint string) map[string]any {
	return check(name, ok, hint)
}

func check(name string, ok bool, hint string) map[string]any {
	m := map[string]any{"name": name, "ok": ok}
	if !ok && hint != "" {
		m["hint"] = hint
	}
	return m
}

// autoStartProxy ensures a proxy is running, starting one if needed.
// Returns the proxy URL.
func autoStartProxy() string {
	if url := findLiveProxy(); url != "" {
		return url
	}

	cfg := loadConfig()
	if cfg.ControlURL == "" || cfg.PrincipalID == "" || cfg.InternalSecret == "" {
		return ""
	}

	// Start proxy as a detached background process
	exe, err := os.Executable()
	if err != nil {
		return ""
	}

	proc, err := os.StartProcess(exe, []string{
		exe, "serve",
		"--control", cfg.ControlURL,
		"--principal", cfg.PrincipalID,
		"--secret", cfg.InternalSecret,
		"--port", strconv.Itoa(cfg.Port),
	}, &os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		return ""
	}
	_ = proc.Release() // detach

	// Wait for discovery file to appear (up to 5s)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if url := findLiveProxy(); url != "" {
			return url
		}
	}
	return ""
}
