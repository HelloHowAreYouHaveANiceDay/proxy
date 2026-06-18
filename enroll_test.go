// Tests for two-tier join token enrollment flow (SPEC SS5/SS6, issue #255).
// Uses an in-process mock control plane that mirrors the real CF Worker logic.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ---- Minimal in-process mock for enrollment token endpoints --------------------

var mockIDCounter int64

func nextMockID(prefix string) string {
	mockIDCounter++
	return fmt.Sprintf("%s-%d", prefix, mockIDCounter)
}

type enrollMockCtrl struct {
	mu               sync.Mutex
	tenants          map[string]bool
	principals       map[string]string // principal_id -> tenant_id
	agents           map[string]string // agent_id -> principal_id
	enrollmentTokens map[string]*mockToken
	adminSecret      string
	srv              *httptest.Server
}

type mockToken struct {
	tenantID    string
	principalID *string // nil = tenant-scoped
	expiresAt   int64
	maxUses     int
	uses        int
}

func newEnrollMockCtrl(t *testing.T, adminSecret string) *enrollMockCtrl {
	t.Helper()
	c := &enrollMockCtrl{
		adminSecret:      adminSecret,
		tenants:          map[string]bool{"default": true},
		principals:       make(map[string]string),
		agents:           make(map[string]string),
		enrollmentTokens: make(map[string]*mockToken),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agents", c.handleAgents)
	mux.HandleFunc("/v1/tenants/", c.handleTenantTokens)
	mux.HandleFunc("/v1/principals/", c.handlePrincipalTokens)
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *enrollMockCtrl) jsonOK(w http.ResponseWriter, body any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (c *enrollMockCtrl) jsonErr(w http.ResponseWriter, kind, msg string, hint string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	m := map[string]any{"ok": false, "error": map[string]string{"kind": kind, "message": msg}}
	if hint != "" {
		m["error"].(map[string]string)["hint"] = hint
	}
	_ = json.NewEncoder(w).Encode(m)
}

func (c *enrollMockCtrl) sha256hex(s string) string {
	import_sha256 := func(data string) []byte {
		// sha256 without importing crypto/sha256 at package level
		// use a simple shim that the real code would do
		h := make([]byte, 32) // placeholder; real test uses actual sha256
		copy(h, []byte(data))
		return h
	}
	_ = import_sha256
	// Simple deterministic hash for test: just hex of the raw token bytes is fine
	// since we control both sides. Use the token value as its own "hash" key.
	return s
}

func (c *enrollMockCtrl) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var body struct {
		PublicKey       string `json:"public_key"`
		EnrollmentToken string `json:"enrollment_token"`
		TenantID        string `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		c.jsonErr(w, "invalid-input", "request body must be JSON", "", 400)
		return
	}
	if body.PublicKey == "" {
		c.jsonErr(w, "invalid-input", "missing required field: public_key", "", 400)
		return
	}

	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()

	var principalID, tenantID string

	if body.EnrollmentToken != "" {
		tok, ok := c.enrollmentTokens[body.EnrollmentToken]
		if !ok {
			c.jsonErr(w, "invalid-token", "enrollment token not found", "request a new token from your tenant admin", 401)
			return
		}
		if tok.expiresAt < now {
			c.jsonErr(w, "invalid-token", "enrollment token expired", "request a new token from your tenant admin", 401)
			return
		}
		if tok.uses >= tok.maxUses {
			c.jsonErr(w, "invalid-token", "enrollment token exhausted", "request a new token from your tenant admin", 401)
			return
		}
		tenantID = tok.tenantID
		tok.uses++
		if tok.principalID == nil {
			// Tenant-scoped: mint new principal
			principalID = nextMockID("pid")
			c.principals[principalID] = tenantID
		} else {
			// Principal-scoped: attach to existing
			principalID = *tok.principalID
			if _, exists := c.principals[principalID]; !exists {
				c.jsonErr(w, "not-found", "principal no longer exists", "", 404)
				return
			}
		}
	} else {
		// Legacy direct-enroll
		tid := body.TenantID
		if tid == "" {
			tid = "default"
		}
		if !c.tenants[tid] {
			c.jsonErr(w, "not-found", fmt.Sprintf("tenant '%s' not found", tid), "", 404)
			return
		}
		tenantID = tid
		principalID = nextMockID("pid")
		c.principals[principalID] = tenantID
	}

	agentID := nextMockID("agent")
	c.agents[agentID] = principalID

	// Generate a fake proxy token
	ptBytes := make([]byte, 8)
	_, _ = rand.Read(ptBytes)
	proxyToken := hex.EncodeToString(ptBytes)

	c.jsonOK(w, map[string]any{
		"ok":           true,
		"principal_id": principalID,
		"agent_id":     agentID,
		"proxy_token":  proxyToken,
	}, 201)
}

func (c *enrollMockCtrl) handleTenantTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("x-admin-secret") != c.adminSecret {
		c.jsonErr(w, "unauthorized", "missing or invalid x-admin-secret", "", 401)
		return
	}
	// Extract tenant_id from path: /v1/tenants/<id>/enrollment-tokens
	path := r.URL.Path
	const prefix = "/v1/tenants/"
	const suffix = "/enrollment-tokens"
	if !hasSuffix(path, suffix) {
		http.NotFound(w, r)
		return
	}
	tenantID := path[len(prefix) : len(path)-len(suffix)]

	c.mu.Lock()
	if !c.tenants[tenantID] {
		c.mu.Unlock()
		c.jsonErr(w, "not-found", fmt.Sprintf("tenant '%s' not found", tenantID), "", 404)
		return
	}

	var body struct {
		ExpiresIn int `json:"expires_in"`
		MaxUses   int `json:"max_uses"`
	}
	body.ExpiresIn = 86400
	body.MaxUses = 1
	_ = json.NewDecoder(r.Body).Decode(&body)

	tok := randomToken()
	c.enrollmentTokens[tok] = &mockToken{
		tenantID:  tenantID,
		expiresAt: time.Now().Unix() + int64(body.ExpiresIn),
		maxUses:   body.MaxUses,
	}
	c.mu.Unlock()

	c.jsonOK(w, map[string]any{
		"ok":         true,
		"token":      tok,
		"expires_at": time.Now().Unix() + int64(body.ExpiresIn),
		"max_uses":   body.MaxUses,
		"kind":       "tenant",
		"tenant_id":  tenantID,
	}, 201)
}

func (c *enrollMockCtrl) handlePrincipalTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("x-admin-secret") != c.adminSecret {
		c.jsonErr(w, "unauthorized", "missing or invalid x-admin-secret", "", 401)
		return
	}
	// /v1/principals/<id>/enrollment-tokens
	path := r.URL.Path
	const prefix = "/v1/principals/"
	const suffix = "/enrollment-tokens"
	if !hasSuffix(path, suffix) {
		http.NotFound(w, r)
		return
	}
	principalID := path[len(prefix) : len(path)-len(suffix)]

	c.mu.Lock()
	tenantID, exists := c.principals[principalID]
	if !exists {
		c.mu.Unlock()
		c.jsonErr(w, "not-found", fmt.Sprintf("principal '%s' not found", principalID), "", 404)
		return
	}

	var body struct {
		ExpiresIn int `json:"expires_in"`
		MaxUses   int `json:"max_uses"`
	}
	body.ExpiresIn = 86400
	body.MaxUses = 1
	_ = json.NewDecoder(r.Body).Decode(&body)

	tok := randomToken()
	pid := principalID
	c.enrollmentTokens[tok] = &mockToken{
		tenantID:    tenantID,
		principalID: &pid,
		expiresAt:   time.Now().Unix() + int64(body.ExpiresIn),
		maxUses:     body.MaxUses,
	}
	c.mu.Unlock()

	c.jsonOK(w, map[string]any{
		"ok":           true,
		"token":        tok,
		"expires_at":   time.Now().Unix() + int64(body.ExpiresIn),
		"max_uses":     body.MaxUses,
		"kind":         "principal",
		"principal_id": principalID,
	}, 201)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- Tests -------------------------------------------------------------------

// TestEnrollment_TenantScopedToken: a tenant-scoped token creates a NEW principal + agent.
// Two enrollments from the same tenant token => two separate principals (each with zero grants).
func TestEnrollment_TenantScopedToken(t *testing.T) {
	ctrl := newEnrollMockCtrl(t, "admin-secret")

	// Mint a tenant-scoped token (max_uses=2 for this test)
	mintReq, _ := http.NewRequest(http.MethodPost,
		ctrl.srv.URL+"/v1/tenants/default/enrollment-tokens",
		bytes.NewBufferString(`{"max_uses":2}`))
	mintReq.Header.Set("Content-Type", "application/json")
	mintReq.Header.Set("X-Admin-Secret", "admin-secret")
	mintResp, err := http.DefaultClient.Do(mintReq)
	if err != nil || mintResp.StatusCode != 201 {
		t.Fatalf("mint tenant token: status=%d err=%v", mintResp.StatusCode, err)
	}
	var mintResult map[string]any
	_ = json.NewDecoder(mintResp.Body).Decode(&mintResult)
	mintResp.Body.Close()

	token, _ := mintResult["token"].(string)
	if token == "" {
		t.Fatal("mint returned empty token")
	}

	enroll := func() (agentID, principalID string) {
		body, _ := json.Marshal(map[string]string{
			"public_key":       "test-key",
			"enrollment_token": token,
		})
		resp, err := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(body)) //nolint:gosec
		if err != nil || resp.StatusCode != 201 {
			t.Fatalf("enroll: status=%d err=%v", resp.StatusCode, err)
		}
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		return result["agent_id"].(string), result["principal_id"].(string)
	}

	// First enrollment: new principal
	agent1, principal1 := enroll()
	if agent1 == "" || principal1 == "" {
		t.Fatal("first enrollment returned empty ids")
	}

	// Agents have zero grants by construction -- the mock has no credentials store seeded.
	ctrl.mu.Lock()
	_, agent1Exists := ctrl.agents[agent1]
	ctrl.mu.Unlock()
	if !agent1Exists {
		t.Errorf("agent1 %q not registered in mock", agent1)
	}

	// Second enrollment: DIFFERENT principal (enrollment != share-the-same-principal)
	agent2, principal2 := enroll()
	if principal2 == principal1 {
		t.Errorf("tenant-scoped enroll: both agents got same principal_id %q; expected distinct principals", principal1)
	}
	if agent2 == agent1 {
		t.Errorf("tenant-scoped enroll: both enrollments returned same agent_id %q", agent1)
	}

	// Third enrollment: token exhausted (max_uses=2)
	body, _ := json.Marshal(map[string]string{"public_key": "k3", "enrollment_token": token})
	resp3, _ := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(body)) //nolint:gosec
	if resp3 != nil {
		defer resp3.Body.Close()
		if resp3.StatusCode != 401 {
			t.Errorf("expected 401 on exhausted token, got %d", resp3.StatusCode)
		}
		var errResult map[string]any
		_ = json.NewDecoder(resp3.Body).Decode(&errResult)
		errObj, _ := errResult["error"].(map[string]any)
		kind, _ := errObj["kind"].(string)
		if kind != "invalid-token" {
			t.Errorf("expected error kind 'invalid-token', got %q", kind)
		}
	}
}

// TestEnrollment_PrincipalScopedToken: a principal-scoped token attaches new agents
// to the SAME principal. Two agents under the same principal would share grants.
func TestEnrollment_PrincipalScopedToken(t *testing.T) {
	ctrl := newEnrollMockCtrl(t, "admin-secret")

	// First: enroll an initial agent (direct / legacy path) to create a principal.
	body1, _ := json.Marshal(map[string]string{"public_key": "pk1"})
	resp1, err := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(body1)) //nolint:gosec
	if err != nil || resp1.StatusCode != 201 {
		t.Fatalf("initial enroll: status=%d err=%v", resp1.StatusCode, err)
	}
	var enroll1 map[string]any
	_ = json.NewDecoder(resp1.Body).Decode(&enroll1)
	resp1.Body.Close()
	principalID, _ := enroll1["principal_id"].(string)
	agent1ID, _ := enroll1["agent_id"].(string)
	if principalID == "" {
		t.Fatal("initial enroll returned empty principal_id")
	}

	// Mint a principal-scoped token (max_uses=2: two more agents can join)
	mintReq, _ := http.NewRequest(http.MethodPost,
		ctrl.srv.URL+"/v1/principals/"+principalID+"/enrollment-tokens",
		bytes.NewBufferString(`{"max_uses":2}`))
	mintReq.Header.Set("Content-Type", "application/json")
	mintReq.Header.Set("X-Admin-Secret", "admin-secret")
	mintResp, _ := http.DefaultClient.Do(mintReq)
	if mintResp.StatusCode != 201 {
		t.Fatalf("mint principal token: status=%d", mintResp.StatusCode)
	}
	var mintResult map[string]any
	_ = json.NewDecoder(mintResp.Body).Decode(&mintResult)
	mintResp.Body.Close()
	token, _ := mintResult["token"].(string)
	if token == "" {
		t.Fatal("mint returned empty token")
	}

	enroll := func(pk string) (agentID, pid string) {
		b, _ := json.Marshal(map[string]string{"public_key": pk, "enrollment_token": token})
		r, err := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(b)) //nolint:gosec
		if err != nil || r.StatusCode != 201 {
			t.Fatalf("enroll %s: status=%d err=%v", pk, r.StatusCode, err)
		}
		var result map[string]any
		_ = json.NewDecoder(r.Body).Decode(&result)
		r.Body.Close()
		return result["agent_id"].(string), result["principal_id"].(string)
	}

	// Two more agents via the principal-scoped token -- both must land under principalID
	agent2, pid2 := enroll("pk2")
	agent3, pid3 := enroll("pk3")

	if pid2 != principalID {
		t.Errorf("agent2 got principal %q, want %q", pid2, principalID)
	}
	if pid3 != principalID {
		t.Errorf("agent3 got principal %q, want %q", pid3, principalID)
	}
	if agent2 == agent1ID || agent3 == agent1ID || agent2 == agent3 {
		t.Errorf("agents must be distinct: agent1=%s agent2=%s agent3=%s", agent1ID, agent2, agent3)
	}
}

// TestEnrollment_InvalidToken: unknown/expired tokens return the standard error envelope.
func TestEnrollment_InvalidToken(t *testing.T) {
	ctrl := newEnrollMockCtrl(t, "admin-secret")

	tryEnroll := func(token string) (statusCode int, kind string) {
		body, _ := json.Marshal(map[string]string{"public_key": "pk", "enrollment_token": token})
		resp, err := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(body)) //nolint:gosec
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		defer resp.Body.Close()
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		errObj, _ := result["error"].(map[string]any)
		k, _ := errObj["kind"].(string)
		return resp.StatusCode, k
	}

	// Unknown token
	code, kind := tryEnroll("unknown-token-xyz")
	if code != 401 || kind != "invalid-token" {
		t.Errorf("unknown token: want 401/invalid-token, got %d/%s", code, kind)
	}

	// Expired token: insert one with expiry in the past
	expiredTok := randomToken()
	ctrl.mu.Lock()
	ctrl.enrollmentTokens[expiredTok] = &mockToken{
		tenantID:  "default",
		expiresAt: time.Now().Unix() - 1, // already expired
		maxUses:   1,
	}
	ctrl.mu.Unlock()

	code2, kind2 := tryEnroll(expiredTok)
	if code2 != 401 || kind2 != "invalid-token" {
		t.Errorf("expired token: want 401/invalid-token, got %d/%s", code2, kind2)
	}

	// Exhausted token: insert one with uses >= max_uses
	exhaustedTok := randomToken()
	ctrl.mu.Lock()
	ctrl.enrollmentTokens[exhaustedTok] = &mockToken{
		tenantID:  "default",
		expiresAt: time.Now().Unix() + 3600,
		maxUses:   1,
		uses:      1, // already exhausted
	}
	ctrl.mu.Unlock()

	code3, kind3 := tryEnroll(exhaustedTok)
	if code3 != 401 || kind3 != "invalid-token" {
		t.Errorf("exhausted token: want 401/invalid-token, got %d/%s", code3, kind3)
	}
}

// TestEnrollment_SeparatePrincipals_DontShareGrants verifies the complement: two
// principals enrolled independently (via two separate tenant-scoped tokens) do not
// share grants. In the mock this means they have distinct principal_ids.
func TestEnrollment_SeparatePrincipals_DontShareGrants(t *testing.T) {
	ctrl := newEnrollMockCtrl(t, "admin-secret")

	mintTenantToken := func() string {
		req, _ := http.NewRequest(http.MethodPost,
			ctrl.srv.URL+"/v1/tenants/default/enrollment-tokens",
			bytes.NewBufferString(`{}`))
		req.Header.Set("X-Admin-Secret", "admin-secret")
		resp, _ := http.DefaultClient.Do(req)
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		tok, _ := result["token"].(string)
		return tok
	}

	enroll := func(tok string) string {
		body, _ := json.Marshal(map[string]string{"public_key": "pk", "enrollment_token": tok})
		resp, _ := http.Post(ctrl.srv.URL+"/v1/agents", "application/json", bytes.NewReader(body)) //nolint:gosec
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		pid, _ := result["principal_id"].(string)
		return pid
	}

	tok1 := mintTenantToken()
	tok2 := mintTenantToken()
	pid1 := enroll(tok1)
	pid2 := enroll(tok2)

	if pid1 == "" || pid2 == "" {
		t.Fatal("enrollment returned empty principal_id")
	}
	if pid1 == pid2 {
		t.Errorf("two separate tenant-token enrollments got same principal_id %q", pid1)
	}
}
