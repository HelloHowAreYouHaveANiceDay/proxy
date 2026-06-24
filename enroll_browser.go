package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// runInitBrowser implements `oauthr init --browser` (RFC 8252 loopback redirect + PKCE S256).
// Opens the control plane consent page in the default browser; waits for the loopback callback;
// exchanges the authorization code for agent credentials and stores them in config.
func runInitBrowser(cfg ProxyConfig) {
	// Generate agent public key.
	pubKeyBytes := make([]byte, 32)
	if _, err := rand.Read(pubKeyBytes); err != nil {
		fail("crypto", fmt.Sprintf("failed to generate public key: %v", err))
	}
	pubKey := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// PKCE S256: verifier = 32 random bytes (base64url); challenge = base64url(SHA-256(verifier)).
	verifierRaw := make([]byte, 32)
	if _, err := rand.Read(verifierRaw); err != nil {
		fail("crypto", "failed to generate PKCE verifier")
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierRaw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// State: 32 random bytes as hex.
	stateRaw := make([]byte, 32)
	if _, err := rand.Read(stateRaw); err != nil {
		fail("crypto", "failed to generate state")
	}
	state := fmt.Sprintf("%x", stateRaw)

	// Bind one-shot loopback listener on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("network", fmt.Sprintf("failed to start loopback listener: %v", err))
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Build the authorize URL for the control plane consent page.
	hostname, _ := os.Hostname()
	qp := url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"redirect_uri":          {redirectURI},
		"display":               {hostname},
	}
	authorizeURL := cfg.ControlURL + "/v1/dashboard/agent-enroll?" + qp.Encode()

	fmt.Fprintf(os.Stderr, "Opening browser for enrollment...\n")
	fmt.Fprintf(os.Stderr, "If the browser does not open automatically, visit:\n  %s\n", authorizeURL)
	openBrowser(authorizeURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	type cbResult struct {
		code  string
		oerr  string
	}
	ch := make(chan cbResult, 1)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			if oauthErr := q.Get("error"); oauthErr != "" {
				w.Header().Set("content-type", "text/html; charset=utf-8")
				fmt.Fprintf(w, "<html><body><h1>Enrollment denied.</h1><p>%s</p><p>You may close this window.</p></body></html>", html.EscapeString(oauthErr))
				select {
				case ch <- cbResult{oerr: oauthErr}:
				default:
				}
				return
			}
			gotState := q.Get("state")
			code := q.Get("code")
			if gotState != state || code == "" {
				http.Error(w, "invalid callback parameters", http.StatusBadRequest)
				return
			}
			w.Header().Set("content-type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<html><body><h1>Enrolled!</h1><p>oauthr is now enrolled. You may close this window.</p></body></html>")
			select {
			case ch <- cbResult{code: code}:
			default:
			}
		}),
	}

	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	var code string
	select {
	case res := <-ch:
		if res.oerr != "" {
			fail("enrollment-denied", res.oerr)
		}
		code = res.code
	case <-ctx.Done():
		fail("timeout", "browser enrollment timed out after 5 minutes")
	}

	// Exchange authorization code + PKCE verifier for agent credentials.
	reqBody, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifier,
		"public_key":    pubKey,
	})
	resp, err := http.Post(cfg.ControlURL+"/v1/agents/enroll/token", "application/json", bytes.NewReader(reqBody)) //nolint:gosec
	if err != nil {
		fail("network", fmt.Sprintf("POST /v1/agents/enroll/token: %v", err))
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

// openBrowser opens the given URL in the system default browser (best-effort).
func openBrowser(rawURL string) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "windows":
		name = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", rawURL}
	case "darwin":
		name = "open"
		args = []string{rawURL}
	default:
		name = "xdg-open"
		args = []string{rawURL}
	}
	_ = exec.Command(name, args...).Start()
}
