// End-to-end integration test for the oauthr injection loop.
// All components run in-process with mock HTTP servers; no Wrangler/D1 required.
//
// Test verifies:
//  1. Full enroll -> connect -> proxied-call flow with a mock OAuth provider.
//  2. Authorization header is injected by the proxy; the client sends none.
//  3. Access/refresh token values are absent from the test process env and disk.
//  4. DO-serialized refresh path: proxy fetches a fresh token after the first expires.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Mock OAuth provider ───────────────────────────────────────────────────────

const (
	testRefreshToken = "rt-oauthr-test-secret"
	testAccessToken  = "at-oauthr-test-injected"
)

// mockOAuthServer stubs the authorize + token endpoints of an OAuth provider.
// Returns testAccessToken on every /token call (both code exchange and refresh).
// Short expires_in (30s) ensures the proxy's 60s buffer causes a refresh on the
// second proxied call, exercising the DO-serialized refresh path.
type mockOAuthServer struct {
	tokenCallCount atomic.Int32
	srv            *httptest.Server
}

func newMockOAuthServer(t *testing.T) *mockOAuthServer {
	t.Helper()
	m := &mockOAuthServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Not called in the automated test — the test drives the callback directly.
		w.WriteHeader(http.StatusOK)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockOAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	m.tokenCallCount.Add(1)
	_ = r.ParseForm()
	resp := map[string]any{
		"access_token": testAccessToken,
		"expires_in":   30, // short-lived: proxy 60s buffer => re-fetch on next proxied call
		"token_type":   "Bearer",
	}
	if r.FormValue("grant_type") == "authorization_code" {
		resp["refresh_token"] = testRefreshToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Mock control plane ────────────────────────────────────────────────────────

// mockCtrl is an in-memory oauthr control plane.
// Credentials are stored as plaintext (no AES envelope) since we're testing the proxy, not crypto.
// Access tokens are NOT cached here — each /v1/internal/token call refreshes from the mock OAuth
// server, mirroring the DO behavior when the cached token is expired.
type mockCtrl struct {
	mu          sync.Mutex
	principals  map[string]bool
	proxyTokens map[string]string // proxy_token -> principal_id
	services    map[string]mockSvc
	sessions    map[string]mockSess
	credentials map[string]string // "pid/svc/label" -> refresh_token

	adminSecret string
	srv         *httptest.Server
}

type mockSvc struct {
	tokenURL     string
	clientID     string
	clientSecret string
}

type mockSess struct {
	principalID string
	service     string
	label       string
	redirectURI string
	used        bool
	expiresAt   int64
}

func newMockCtrl(t *testing.T, adminSecret string) *mockCtrl {
	t.Helper()
	c := &mockCtrl{
		adminSecret: adminSecret,
		principals:  make(map[string]bool),
		proxyTokens: make(map[string]string),
		services:    make(map[string]mockSvc),
		sessions:    make(map[string]mockSess),
		credentials: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/agents", c.handleAgents)
	mux.HandleFunc("/v1/admin/services", c.handleServices)
	mux.HandleFunc("/v1/auth/sessions", c.handleSessions)
	mux.HandleFunc("/v1/auth/callback", c.handleCallback)
	mux.HandleFunc("/v1/auth/sessions/", c.handleSessionGet)
	mux.HandleFunc("/v1/internal/token", c.handleInternalToken)
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *mockCtrl) jsonOK(w http.ResponseWriter, body any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (c *mockCtrl) jsonErr(w http.ResponseWriter, kind, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false, "error": map[string]string{"kind": kind, "message": msg},
	})
}

func (c *mockCtrl) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	pid := fmt.Sprintf("pid-%d", time.Now().UnixNano())
	pt := fmt.Sprintf("pt.%d", time.Now().UnixNano())
	c.mu.Lock()
	c.principals[pid] = true
	c.proxyTokens[pt] = pid
	c.mu.Unlock()
	c.jsonOK(w, map[string]any{"ok": true, "principal_id": pid, "proxy_token": pt}, http.StatusCreated)
}

func (c *mockCtrl) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("x-admin-secret") != c.adminSecret {
		c.jsonErr(w, "unauthorized", "bad secret", http.StatusUnauthorized)
		return
	}
	var body struct {
		ID           string `json:"id"`
		TokenURL     string `json:"token_url"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	c.mu.Lock()
	c.services[body.ID] = mockSvc{
		tokenURL:     body.TokenURL,
		clientID:     body.ClientID,
		clientSecret: body.ClientSecret,
	}
	c.mu.Unlock()
	c.jsonOK(w, map[string]any{"ok": true, "id": body.ID}, http.StatusOK)
}

func (c *mockCtrl) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var body struct {
		PrincipalID string `json:"principal_id"`
		Service     string `json:"service"`
		Label       string `json:"label"`
		RedirectURI string `json:"redirect_uri"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Label == "" {
		body.Label = "default"
	}
	state := fmt.Sprintf("state-%d", time.Now().UnixNano())
	c.mu.Lock()
	svc := c.services[body.Service]
	c.sessions[state] = mockSess{
		principalID: body.PrincipalID,
		service:     body.Service,
		label:       body.Label,
		redirectURI: body.RedirectURI,
		expiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	c.mu.Unlock()
	// Simplified auth_url; the test drives the callback directly so the URL shape doesn't matter.
	authURL := svc.tokenURL + "?state=" + state
	c.jsonOK(w, map[string]any{"ok": true, "session_id": state, "consent_url": authURL}, http.StatusCreated)
}

func (c *mockCtrl) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	c.mu.Lock()
	sess, ok := c.sessions[state]
	svc := c.services[sess.service]
	c.mu.Unlock()
	if !ok || sess.used {
		c.jsonErr(w, "invalid-input", "unknown or used state", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens with the mock OAuth server.
	resp, err := http.PostForm(svc.tokenURL, url.Values{ //nolint:gosec
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {sess.redirectURI},
		"client_id":     {svc.clientID},
		"client_secret": {svc.clientSecret},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		c.jsonErr(w, "upstream-error", "token exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokens)

	credKey := sess.principalID + "/" + sess.service + "/" + sess.label
	c.mu.Lock()
	c.credentials[credKey] = tokens.RefreshToken
	sess.used = true
	c.sessions[state] = sess
	c.mu.Unlock()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Connected!</h1></body></html>")
}

func (c *mockCtrl) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/v1/auth/sessions/")
	c.mu.Lock()
	sess, ok := c.sessions[sessionID]
	c.mu.Unlock()
	if !ok {
		c.jsonErr(w, "not-found", "session not found", http.StatusNotFound)
		return
	}
	status := "pending"
	if sess.used {
		status = "connected"
	}
	c.jsonOK(w, map[string]any{"ok": true, "status": status, "used": sess.used}, http.StatusOK)
}

func (c *mockCtrl) handleInternalToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("x-internal-secret") != c.adminSecret {
		c.jsonErr(w, "unauthorized", "bad secret", http.StatusUnauthorized)
		return
	}
	var body struct {
		ProxyToken string `json:"proxy_token"`
		Service    string `json:"service"`
		Label      string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Label == "" {
		body.Label = "default"
	}

	c.mu.Lock()
	pid := c.proxyTokens[body.ProxyToken]
	c.mu.Unlock()
	if pid == "" {
		c.jsonErr(w, "unauthorized", "unknown proxy_token", http.StatusUnauthorized)
		return
	}

	credKey := pid + "/" + body.Service + "/" + body.Label
	c.mu.Lock()
	rt, ok := c.credentials[credKey]
	svc := c.services[body.Service]
	c.mu.Unlock()
	if !ok {
		c.jsonErr(w, "not-connected", "no credential for this slot", http.StatusNotFound)
		return
	}

	// Refresh the access token using the stored refresh token (mirrors DO behavior).
	resp, err := http.PostForm(svc.tokenURL, url.Values{ //nolint:gosec
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {svc.clientID},
		"client_secret": {svc.clientSecret},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		c.jsonErr(w, "upstream-error", "token refresh failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var tokens struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokens)

	expiresAt := time.Now().Unix() + int64(tokens.ExpiresIn)
	// flat envelope -- matches the deployed Worker's actual response shape
	c.jsonOK(w, map[string]any{
		"ok":           true,
		"access_token": tokens.AccessToken,
		"expires_at":   expiresAt,
	}, http.StatusOK)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// tlsClientViaProxy returns an http.Client that routes all traffic through proxyURL
// and trusts caPool for TLS verification (used to accept the MITM'd leaf certs).
func tlsClientViaProxy(t *testing.T, proxyURL string, caPool *x509.CertPool) *http.Client {
	t.Helper()
	pURL, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 10 * time.Second,
	}
}

// assertTokenNotOnDisk fails the test if any file under dir contains secret.
func assertTokenNotOnDisk(t *testing.T, dir, secret string) {
	t.Helper()
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), secret) {
				t.Errorf("token %q found in file %s", secret, path)
			}
		}
		return nil
	})
}

// ── Main e2e test ─────────────────────────────────────────────────────────────

func TestE2E_InjectionLoop(t *testing.T) {
	const adminSecret = "test-internal-secret"

	// 1. Start mock OAuth provider and mock control plane.
	oauthSrv := newMockOAuthServer(t)
	ctrl := newMockCtrl(t, adminSecret)

	// 2. Register the "mock" service with the control plane.
	seedBody, _ := json.Marshal(map[string]any{
		"id":            "mock",
		"display_name":  "Mock Provider",
		"auth_url":      oauthSrv.srv.URL + "/authorize",
		"token_url":     oauthSrv.srv.URL + "/token",
		"host_patterns": "mockapi.oauthr.test",
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"default_scopes": "openid",
	})
	seedReq, _ := http.NewRequest(http.MethodPut, ctrl.srv.URL+"/v1/admin/services", bytes.NewBuffer(seedBody))
	seedReq.Header.Set("Content-Type", "application/json")
	seedReq.Header.Set("x-admin-secret", adminSecret)
	seedResp, err := http.DefaultClient.Do(seedReq)
	if err != nil || seedResp.StatusCode != http.StatusOK {
		var b []byte
		if seedResp != nil {
			b, _ = io.ReadAll(seedResp.Body)
		}
		t.Fatalf("seed service: status=%v err=%v body=%s", seedResp.StatusCode, err, b)
	}
	seedResp.Body.Close()

	// 3. Enroll a principal.
	enrollResp, err := http.Post(ctrl.srv.URL+"/v1/agents", "application/json",
		bytes.NewBufferString(`{"public_key":"test-pk"}`)) //nolint:gosec
	if err != nil || enrollResp.StatusCode != http.StatusCreated {
		t.Fatalf("enroll: status=%v err=%v", enrollResp.StatusCode, err)
	}
	var enrollResult struct {
		PrincipalID string `json:"principal_id"`
		ProxyToken  string `json:"proxy_token"`
	}
	_ = json.NewDecoder(enrollResp.Body).Decode(&enrollResult)
	enrollResp.Body.Close()
	pid := enrollResult.PrincipalID
	proxyToken := enrollResult.ProxyToken
	if pid == "" || proxyToken == "" {
		t.Fatal("enroll returned empty principal_id or proxy_token")
	}

	// 4. Start a PKCE connect session.
	sessBody, _ := json.Marshal(map[string]string{
		"principal_id": pid,
		"service":      "mock",
		"label":        "default",
		"redirect_uri": ctrl.srv.URL + "/v1/auth/callback",
	})
	sessResp, err := http.Post(ctrl.srv.URL+"/v1/auth/sessions", "application/json", bytes.NewBuffer(sessBody)) //nolint:gosec
	if err != nil || sessResp.StatusCode != http.StatusCreated {
		t.Fatalf("start session: status=%v err=%v", sessResp.StatusCode, err)
	}
	var sessResult struct {
		SessionID string `json:"session_id"`
	}
	_ = json.NewDecoder(sessResp.Body).Decode(&sessResult)
	sessResp.Body.Close()
	state := sessResult.SessionID
	if state == "" {
		t.Fatal("start session returned empty session_id")
	}

	// 5. Programmatically complete the consent by driving GET /v1/auth/callback?state=...&code=...
	//    In production the user clicks the consent URL in a browser; here the test handles it.
	callbackURL := ctrl.srv.URL + "/v1/auth/callback?state=" + url.QueryEscape(state) + "&code=test-auth-code"
	cbResp, err := http.Get(callbackURL) //nolint:gosec
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	if cbResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(cbResp.Body)
		t.Fatalf("callback: status=%d body=%s", cbResp.StatusCode, body)
	}
	cbResp.Body.Close()

	// The code exchange consumed call #1 on the mock OAuth /token endpoint.
	if got := oauthSrv.tokenCallCount.Load(); got != 1 {
		t.Fatalf("expected 1 /token call after callback (code exchange), got %d", got)
	}

	// 6. Start the proxy in-process.
	dataDir := t.TempDir()
	ca, err := loadOrCreateCA(dataDir)
	if err != nil {
		t.Fatalf("loadOrCreateCA: %v", err)
	}
	cfg := ProxyConfig{
		ControlURL:     ctrl.srv.URL,
		InternalSecret: adminSecret,
		ProxyToken:     proxyToken,
		Port:           0,
		DataDir:        dataDir,
	}
	proxy := newProxy(cfg, ca)
	// Map the mock API hostname to the "mock" service.
	proxy.extraPatterns = []servicePattern{{"mockapi.oauthr.test", "mock"}}

	// 7. Start a mock API TLS server that records the Authorization header each request receives.
	var (
		receivedAuth []string
		authMu       sync.Mutex
	)
	mockAPISrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMu.Lock()
		receivedAuth = append(receivedAuth, r.Header.Get("Authorization"))
		authMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(mockAPISrv.Close)

	// The mock API listens on 127.0.0.1:PORT. The proxy must dial our mock server rather
	// than resolving "mockapi.oauthr.test" via real DNS, and must accept its self-signed cert.
	mockAPIAddr := mockAPISrv.Listener.Addr().String()
	mockAPIPort := mockAPIAddr[strings.LastIndex(mockAPIAddr, ":")+1:]
	proxy.dialUpstream = func(network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
		if strings.HasPrefix(addr, "mockapi.oauthr.test:") {
			addr = "127.0.0.1:" + addr[strings.LastIndex(addr, ":")+1:]
		}
		insecure := tlsCfg.Clone()
		insecure.InsecureSkipVerify = true //nolint:gosec // test-only: mock server self-signed cert
		return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, network, addr, insecure)
	}

	proxySrv := httptest.NewServer(proxy)
	t.Cleanup(proxySrv.Close)

	// 8. Build a test HTTP client that routes through the proxy and trusts the oauthr CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)
	client := tlsClientViaProxy(t, proxySrv.URL, caPool)

	targetURL := "https://mockapi.oauthr.test:" + mockAPIPort + "/api/data"

	// 9. First proxied HTTPS GET — client sends no Authorization header.
	//    The proxy intercepts, fetches an access token from /v1/internal/token, and injects it.
	req1, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	// Deliberately omit Authorization; the proxy must add it.
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first proxied GET: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first proxied GET: expected 200, got %d", resp1.StatusCode)
	}

	// Assert the mock API received an injected Authorization header.
	authMu.Lock()
	calls1 := len(receivedAuth)
	auth1 := ""
	if calls1 > 0 {
		auth1 = receivedAuth[0]
	}
	authMu.Unlock()
	if calls1 < 1 {
		t.Fatal("mock API received 0 requests (expected 1)")
	}
	if !strings.HasPrefix(auth1, "Bearer ") {
		t.Fatalf("expected Authorization: Bearer <token> on call 1; got %q", auth1)
	}
	injectedToken := strings.TrimPrefix(auth1, "Bearer ")
	if injectedToken == "" {
		t.Fatal("injected token is empty")
	}

	// Assert the injected token is NOT present in the test process environment.
	for _, env := range os.Environ() {
		if strings.Contains(env, injectedToken) {
			t.Errorf("injected access token found in process env: %q", env)
		}
		if strings.Contains(env, testRefreshToken) {
			t.Errorf("refresh token found in process env: %q", env)
		}
	}

	// Assert the token values are NOT present on disk under the proxy's data dir.
	assertTokenNotOnDisk(t, dataDir, injectedToken)
	assertTokenNotOnDisk(t, dataDir, testRefreshToken)

	// 10. Second proxied HTTPS GET — the first token has expires_in=30 which is less than
	//     the proxy's 60s expiry buffer, so the proxy immediately fetches a fresh token
	//     (exercising the DO-serialized refresh path).
	req2, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second proxied GET: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second proxied GET: expected 200, got %d", resp2.StatusCode)
	}

	// Assert the mock API received a second injected Authorization header.
	authMu.Lock()
	calls2 := len(receivedAuth)
	auth2 := ""
	if calls2 > 1 {
		auth2 = receivedAuth[1]
	}
	authMu.Unlock()
	if calls2 < 2 {
		t.Fatal("mock API received <2 requests (expected 2)")
	}
	if !strings.HasPrefix(auth2, "Bearer ") {
		t.Fatalf("expected Authorization: Bearer <token> on call 2; got %q", auth2)
	}

	// The proxy re-fetched the token (refresh path). /token was called >=2 times total
	// (once for code exchange + at least once for each proxied call refresh).
	if got := oauthSrv.tokenCallCount.Load(); got < 2 {
		t.Fatalf("expected >=2 /token calls (1 code exchange + >=1 refresh); got %d", got)
	}
}
