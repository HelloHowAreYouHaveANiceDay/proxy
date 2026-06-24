package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runInitDevice implements `oauthr init --device` (RFC 8628 device authorization grant).
// Prints the verification URI and user code to stderr; polls until the user approves (or
// the code expires); stores the resulting agent credentials in config.
func runInitDevice(cfg ProxyConfig) {
	// Generate agent public key upfront; sent with the device/code request so the server
	// can create the agent record as soon as the user approves.
	pubKeyBytes := make([]byte, 32)
	if _, err := rand.Read(pubKeyBytes); err != nil {
		fail("crypto", fmt.Sprintf("failed to generate public key: %v", err))
	}
	pubKey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	hostname, _ := os.Hostname()

	// POST /v1/agents/enroll/device/code -- start the device authorization flow.
	codeBody, _ := json.Marshal(map[string]string{
		"public_key": pubKey,
		"display":    hostname,
	})
	codeResp, err := http.Post(cfg.ControlURL+"/v1/agents/enroll/device/code", "application/json", bytes.NewReader(codeBody)) //nolint:gosec
	if err != nil {
		fail("network", fmt.Sprintf("POST /v1/agents/enroll/device/code: %v", err))
	}
	defer codeResp.Body.Close()

	var dc map[string]any
	if err := json.NewDecoder(codeResp.Body).Decode(&dc); err != nil {
		fail("parse", "unexpected response from device/code endpoint")
	}
	if ok, _ := dc["ok"].(bool); !ok {
		errObj, _ := dc["error"].(map[string]any)
		kind, _ := errObj["kind"].(string)
		msg, _ := errObj["message"].(string)
		fail(kind, msg)
	}

	deviceCode, _ := dc["device_code"].(string)
	userCode, _ := dc["user_code"].(string)
	verificationURI, _ := dc["verification_uri"].(string)
	interval, _ := dc["interval"].(float64)
	expiresIn, _ := dc["expires_in"].(float64)
	if interval < 1 {
		interval = 5
	}
	if expiresIn < 1 {
		expiresIn = 300
	}

	fmt.Fprintf(os.Stderr, "On any device, open:  %s\n", verificationURI)
	fmt.Fprintf(os.Stderr, "Enter the code:       %s\n", userCode)
	fmt.Fprintf(os.Stderr, "Waiting for approval (expires in %.0fs)...\n", expiresIn)

	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)
	pollInterval := time.Duration(interval) * time.Second

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		pollBody, _ := json.Marshal(map[string]string{"device_code": deviceCode})
		pollResp, pollErr := http.Post(cfg.ControlURL+"/v1/agents/enroll/device/token", "application/json", bytes.NewReader(pollBody)) //nolint:gosec
		if pollErr != nil {
			// Transient network error; keep polling until deadline.
			continue
		}

		var raw map[string]any
		_ = json.NewDecoder(pollResp.Body).Decode(&raw)
		pollResp.Body.Close()

		if ok, _ := raw["ok"].(bool); ok {
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
			return
		}

		errObj, _ := raw["error"].(map[string]any)
		kind, _ := errObj["kind"].(string)
		switch kind {
		case "authorization_pending":
			// Keep polling.
		case "slow_down":
			pollInterval += 5 * time.Second
		default:
			msg, _ := errObj["message"].(string)
			fail(kind, msg)
		}
	}

	fail("timeout", "device enrollment timed out -- the code may have expired; restart enrollment to try again")
}
