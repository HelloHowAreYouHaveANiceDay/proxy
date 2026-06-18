package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ProxyConfig is the runtime configuration for the injecting proxy.
// Values are resolved: config file < environment variables < CLI flags.
type ProxyConfig struct {
	ControlURL     string `json:"control_url"`      // OAUTHR_CONTROL_URL
	InternalSecret string `json:"internal_secret"`  // OAUTHR_INTERNAL_SECRET
	ProxyToken     string `json:"proxy_token"`      // OAUTHR_PROXY_TOKEN (Phase 2: agent leash)
	PrincipalID    string `json:"principal_id"`     // OAUTHR_PRINCIPAL_ID (Phase 1 backward compat)
	AgentID        string `json:"agent_id"`         // OAUTHR_AGENT_ID (informational)
	Port           int    `json:"port"`             // default 8080
	DataDir        string `json:"data_dir"`         // default ~/.oauthr
}

// loadConfig reads ~/.oauthr/config.json and overlays environment variables.
func loadConfig() ProxyConfig {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".oauthr")

	cfg := ProxyConfig{
		Port:    8080,
		DataDir: dataDir,
	}

	path := filepath.Join(dataDir, "config.json")
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}

	// env overrides
	if v := os.Getenv("OAUTHR_CONTROL_URL"); v != "" {
		cfg.ControlURL = v
	}
	if v := os.Getenv("OAUTHR_INTERNAL_SECRET"); v != "" {
		cfg.InternalSecret = v
	}
	if v := os.Getenv("OAUTHR_PROXY_TOKEN"); v != "" {
		cfg.ProxyToken = v
	}
	if v := os.Getenv("OAUTHR_PRINCIPAL_ID"); v != "" {
		cfg.PrincipalID = v
	}
	if v := os.Getenv("OAUTHR_AGENT_ID"); v != "" {
		cfg.AgentID = v
	}

	return cfg
}

// saveConfig writes cfg to ~/.oauthr/config.json.
func saveConfig(cfg ProxyConfig) error {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cfg.DataDir, "config.json"), b, 0600)
}
