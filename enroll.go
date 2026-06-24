package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
)

// runInit implements `oauthr init`.
// Supports three enrollment modes:
//   --enrollment-token <tok>  join via a pre-issued token (also OAUTHR_ENROLLMENT_TOKEN)
//   --browser                 browser loopback + PKCE (RFC 8252, interactive desktop)
//   --device                  device authorization grant (RFC 8628, headless / SSH / CI)
//
// Idempotent: if agent_id + proxy_token are already stored, re-prints them without re-enrolling.
func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	enrollToken := fs.String("enrollment-token", "", "join token (also OAUTHR_ENROLLMENT_TOKEN)")
	control := fs.String("control", "", "control plane URL (also OAUTHR_CONTROL_URL)")
	browserFlow := fs.Bool("browser", false, "enroll via browser loopback + PKCE (RFC 8252)")
	deviceFlow := fs.Bool("device", false, "enroll via device authorization grant (RFC 8628, headless)")
	_ = fs.Parse(args)

	cfg := loadConfig()

	if *control != "" {
		cfg.ControlURL = *control
	}
	if cfg.ControlURL == "" {
		fail("config", "control URL required: set OAUTHR_CONTROL_URL or --control flag")
	}

	// Idempotent: already enrolled with a stored identity -- return it without re-enrolling.
	if cfg.AgentID != "" && cfg.ProxyToken != "" {
		emit(map[string]any{
			"ok": true,
			"result": map[string]any{
				"agent_id":     cfg.AgentID,
				"principal_id": cfg.PrincipalID,
				"status":       "already-enrolled",
			},
		})
		fmt.Fprintf(os.Stderr, "OAUTHR_ENROLLED_OK %s\n", cfg.AgentID)
		return
	}

	// Dispatch to the appropriate enrollment flow.
	if *browserFlow {
		runInitBrowser(cfg)
		return
	}
	if *deviceFlow {
		runInitDevice(cfg)
		return
	}

	tok := *enrollToken
	if tok == "" {
		tok = os.Getenv("OAUTHR_ENROLLMENT_TOKEN")
	}
	if tok == "" {
		fail("config", "enrollment token required: use --enrollment-token, --browser, or --device (see oauthr init --help)")
	}

	// Generate a random public key (placeholder for Phase 2; DPoP keypair in Phase 3).
	pubKeyBytes := make([]byte, 32)
	if _, err := rand.Read(pubKeyBytes); err != nil {
		fail("crypto", fmt.Sprintf("failed to generate public key: %v", err))
	}
	pubKey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	reqBody, _ := json.Marshal(map[string]string{
		"public_key":       pubKey,
		"enrollment_token": tok,
	})

	resp, err := http.Post(cfg.ControlURL+"/v1/agents", "application/json", bytes.NewReader(reqBody)) //nolint:gosec
	if err != nil {
		fail("network", fmt.Sprintf("POST /v1/agents: %v", err))
	}
	defer resp.Body.Close()

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		fail("parse", fmt.Sprintf("unexpected response: %v", err))
	}

	if ok, _ := raw["ok"].(bool); !ok {
		errObj, _ := raw["error"].(map[string]any)
		kind, _ := errObj["kind"].(string)
		msg, _ := errObj["message"].(string)
		fail(kind, msg)
	}

	agentID, _ := raw["agent_id"].(string)
	principalID, _ := raw["principal_id"].(string)
	proxyToken, _ := raw["proxy_token"].(string)

	if agentID == "" || proxyToken == "" {
		fail("parse", "control plane returned empty agent_id or proxy_token")
	}

	cfg.AgentID = agentID
	cfg.PrincipalID = principalID
	cfg.ProxyToken = proxyToken
	if err := saveConfig(cfg); err != nil {
		fail("config", fmt.Sprintf("failed to save config: %v", err))
	}

	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"agent_id":     agentID,
			"principal_id": principalID,
		},
	})
	fmt.Fprintf(os.Stderr, "OAUTHR_ENROLLED_OK %s\n", agentID)
}

// runPrincipalToken implements `oauthr principal token [<principal_id>]`.
// Mints a principal-scoped join token so another agent can attach to the same principal.
// Requires OAUTHR_ADMIN_SECRET.
func runPrincipalToken(args []string) {
	fs := flag.NewFlagSet("principal token", flag.ExitOnError)
	expiresIn := fs.Int("expires-in", 86400, "token lifetime in seconds (default 24h)")
	maxUses := fs.Int("max-uses", 1, "maximum number of enrollments (default 1)")
	_ = fs.Parse(args)

	cfg := loadConfig()
	if cfg.ControlURL == "" {
		fail("config", "OAUTHR_CONTROL_URL not set")
	}

	principalID := fs.Arg(0)
	if principalID == "" {
		principalID = cfg.PrincipalID
	}
	if principalID == "" {
		fail("config", "principal_id required: pass as argument or set OAUTHR_PRINCIPAL_ID")
	}

	adminSecret := os.Getenv("OAUTHR_ADMIN_SECRET")
	if adminSecret == "" {
		fail("config", "OAUTHR_ADMIN_SECRET not set")
	}

	reqBody, _ := json.Marshal(map[string]any{
		"expires_in": *expiresIn,
		"max_uses":   *maxUses,
	})

	req, _ := http.NewRequest(http.MethodPost,
		cfg.ControlURL+"/v1/principals/"+principalID+"/enrollment-tokens",
		bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", adminSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("network", fmt.Sprintf("POST /v1/principals/.../enrollment-tokens: %v", err))
	}
	defer resp.Body.Close()

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		fail("parse", fmt.Sprintf("unexpected response: %v", err))
	}

	if ok, _ := raw["ok"].(bool); !ok {
		errObj, _ := raw["error"].(map[string]any)
		kind, _ := errObj["kind"].(string)
		msg, _ := errObj["message"].(string)
		fail(kind, msg)
	}

	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"token":        raw["token"],
			"expires_at":   raw["expires_at"],
			"max_uses":     raw["max_uses"],
			"principal_id": principalID,
			"kind":         "principal",
		},
	})
}
