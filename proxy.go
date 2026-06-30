package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// servicePattern maps a hostname pattern to a service name.
// Pattern matching: exact or wildcard prefix (*.googleapis.com).
type servicePattern struct {
	pattern string
	service string
}

var builtinServicePatterns = []servicePattern{
	// Google
	{"*.googleapis.com", "google"},
	{"oauth2.googleapis.com", "google"},
	{"accounts.google.com", "google"},
	// Linear
	{"api.linear.app", "linear"},
	// Dropbox
	{"api.dropboxapi.com", "dropbox"},
	// Box
	{"api.box.com", "box"},
	// Salesforce -- instance_url is per-org (*.salesforce.com covers all orgs and sandboxes)
	{"*.salesforce.com", "salesforce"},
	// HubSpot
	{"api.hubapi.com", "hubspot"},
	// Stripe Connect
	{"api.stripe.com", "stripe"},
	// Discord
	{"discord.com", "discord"},
	// Zoom
	{"api.zoom.us", "zoom"},
	// X (Twitter)
	{"api.twitter.com", "x"},
	// Figma
	{"api.figma.com", "figma"},
	// Shopify -- shop domain is per-merchant (*.myshopify.com covers all shops)
	{"*.myshopify.com", "shopify"},
}

func matchPattern(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		if strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}

// tokenEntry is a cached token with expiry.
type tokenEntry struct {
	accessToken string
	expiresAt   int64 // unix seconds
}

// cpPatternsTTL is how often the proxy re-fetches service patterns from the control plane.
const cpPatternsTTL = 5 * time.Minute

// Proxy is the injecting MITM proxy.
type Proxy struct {
	cfg          ProxyConfig
	ca           *CA
	extraPatterns []servicePattern // additional host→service mappings (used in tests)
	// dialUpstream dials the real upstream TLS connection. Defaults to tls.DialWithDialer;
	// tests override this to accept self-signed mock-server certs.
	dialUpstream func(network, addr string, cfg *tls.Config) (net.Conn, error)

	mu     sync.Mutex
	tokens map[string]tokenEntry // key: "service/label"

	cpMu      sync.RWMutex
	cpPatterns []servicePattern // fetched from control plane; refreshed every cpPatternsTTL
}

func newProxy(cfg ProxyConfig, ca *CA) *Proxy {
	p := &Proxy{
		cfg:          cfg,
		ca:           ca,
		tokens:       make(map[string]tokenEntry),
		dialUpstream: defaultDialUpstream,
	}
	if cfg.ControlURL != "" {
		go p.runServicePatternRefresher()
	}
	return p
}

// runServicePatternRefresher fetches service host_patterns from the control plane at startup
// and refreshes them every cpPatternsTTL so new services registered via PUT /v1/admin/services
// are picked up without a proxy restart or rebuild.
func (p *Proxy) runServicePatternRefresher() {
	for {
		p.refreshServicePatterns()
		time.Sleep(cpPatternsTTL)
	}
}

// refreshServicePatterns fetches the current service list from the control plane and updates
// cpPatterns. A failed fetch is silently ignored; the previous cpPatterns (or an empty slice)
// remain in effect and builtinServicePatterns still cover the built-in providers.
func (p *Proxy) refreshServicePatterns() {
	req, err := http.NewRequest(http.MethodGet, p.cfg.ControlURL+"/v1/internal/services", nil)
	if err != nil {
		return
	}
	if p.cfg.ProxyToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.ProxyToken)
	} else if p.cfg.InternalSecret != "" {
		req.Header.Set("X-Internal-Secret", p.cfg.InternalSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var result struct {
		OK       bool `json:"ok"`
		Services []struct {
			Service      string `json:"service"`
			HostPatterns string `json:"host_patterns"`
		} `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.OK {
		return
	}

	patterns := make([]servicePattern, 0)
	for _, s := range result.Services {
		for _, pat := range strings.Fields(s.HostPatterns) {
			patterns = append(patterns, servicePattern{pattern: pat, service: s.Service})
		}
	}

	p.cpMu.Lock()
	p.cpPatterns = patterns
	p.cpMu.Unlock()
}

func defaultDialUpstream(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, network, addr, cfg)
}

// matchService maps host (with optional port) to a service name.
// Priority: extraPatterns (test injection) > cpPatterns (control plane) > builtinServicePatterns.
func (p *Proxy) matchService(host string) string {
	h := host
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}
	for _, sp := range p.extraPatterns {
		if matchPattern(sp.pattern, h) {
			return sp.service
		}
	}
	p.cpMu.RLock()
	cp := p.cpPatterns
	p.cpMu.RUnlock()
	for _, sp := range cp {
		if matchPattern(sp.pattern, h) {
			return sp.service
		}
	}
	for _, sp := range builtinServicePatterns {
		if matchPattern(sp.pattern, h) {
			return sp.service
		}
	}
	return ""
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Liveness probe: a direct (non-proxied) GET /healthz returns 200 so clients
	// (e.g. the bim-linear driver) can confirm the proxy is up before routing
	// HTTPS through it. Proxied requests use absolute-form request URIs
	// (r.URL.IsAbs()), so this never shadows a real upstream /healthz.
	if r.Method == http.MethodGet && !r.URL.IsAbs() && r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handleCONNECT intercepts CONNECT tunnels, performs TLS MITM, and injects Authorization.
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host := r.Host // e.g. "oauth2.googleapis.com:443"

	// Acknowledge the CONNECT
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	hostname := host
	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	service := p.matchService(host)
	if service == "" {
		// Unknown host — pass through unmodified (raw TCP tunnel to upstream)
		p.rawTunnel(conn, host)
		return
	}

	// MITM: wrap client connection in TLS
	leafCert, err := p.ca.leafFor(hostname)
	if err != nil {
		return
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{*leafCert}}
	tlsConn := tls.Server(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// Read HTTP requests from the MITM'd connection and forward them
	label := extractLabel(r)
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host

		// Inject Authorization
		tok, err := p.getToken(service, label)
		if err == nil && tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}

		// Forward to real upstream
		resp, err := p.forwardRequest(req, host)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if err := resp.Write(tlsConn); err != nil {
			return
		}
	}
}

// handlePlainHTTP handles non-CONNECT proxy requests (HTTP).
func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}

	service := p.matchService(host)
	label := extractLabel(r)

	if service != "" {
		tok, err := p.getToken(service, label)
		if err == nil && tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	// Remove proxy-specific headers
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = host
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// rawTunnel bridges conn ↔ upstream over plain TCP (unknown host, no MITM).
func (p *Proxy) rawTunnel(conn net.Conn, host string) {
	up, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// getToken returns a cached or freshly-fetched access token for (service, label).
// Token is never written to disk — cache is in-process memory only.
func (p *Proxy) getToken(service, label string) (string, error) {
	key := service + "/" + label

	p.mu.Lock()
	if e, ok := p.tokens[key]; ok && time.Now().Unix() < e.expiresAt-60 {
		tok := e.accessToken
		p.mu.Unlock()
		return tok, nil
	}
	p.mu.Unlock()

	// The new control plane requires proxy_token in the request body.
	// PrincipalID-only (Phase 1) is rejected by the server; callers must enroll
	// via `oauthr init` to obtain a proxy_token before token minting works.
	if p.cfg.ProxyToken == "" {
		return "", fmt.Errorf("proxy_token not configured: run `oauthr init` to enroll")
	}
	tokenReqBody := map[string]string{"service": service, "label": label, "proxy_token": p.cfg.ProxyToken}
	body, _ := json.Marshal(tokenReqBody)
	req, err := http.NewRequest(http.MethodPost, p.cfg.ControlURL+"/v1/internal/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	// X-Internal-Secret is the shared transport credential. Only send it when
	// explicitly configured; ProxyToken is a per-agent capability token and must
	// never be used as a substitute for the shared secret.
	if p.cfg.InternalSecret != "" {
		req.Header.Set("X-Internal-Secret", p.cfg.InternalSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		OK          bool   `json:"ok"`
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
		Error       struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if !result.OK {
		return "", fmt.Errorf("control plane: %s: %s", result.Error.Kind, result.Error.Message)
	}

	p.mu.Lock()
	p.tokens[key] = tokenEntry{
		accessToken: result.AccessToken,
		expiresAt:   result.ExpiresAt,
	}
	p.mu.Unlock()

	return result.AccessToken, nil
}

// extractLabel reads the label from Proxy-Authorization (Basic scheme, username = label).
// Falls back to "default".
//
// HTTP clients that use HTTPS_PROXY=http://label:@proxy:port send the credential as
// Proxy-Authorization: Basic base64(label:). Go's BasicAuth() reads the Authorization
// header, so we copy the Proxy-Authorization value into a synthetic Authorization header
// on a throw-away request to reuse the stdlib base64 decode.
func extractLabel(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "default"
	}
	// Put the Proxy-Authorization value into Authorization so BasicAuth() can parse it.
	dummy := &http.Request{Header: make(http.Header)}
	dummy.Header.Set("Authorization", auth)
	if u, _, ok := dummy.BasicAuth(); ok && u != "" {
		return u
	}
	return "default"
}

// connBody wraps a response body and closes the underlying connection once the body is closed,
// keeping the connection alive until the full response has been streamed to the client.
type connBody struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connBody) Close() error {
	err := c.ReadCloser.Close()
	c.conn.Close()
	return err
}

// forwardRequest sends req to the real upstream (over TLS for HTTPS hosts).
// The returned response body owns upConn; closing the body also closes the connection.
func (p *Proxy) forwardRequest(req *http.Request, host string) (*http.Response, error) {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.RequestURI = ""

	upConn, err := p.dialUpstream("tcp", host, &tls.Config{ServerName: req.URL.Hostname()})
	if err != nil {
		return nil, err
	}

	if err := req.Write(upConn); err != nil {
		upConn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(upConn), req)
	if err != nil {
		upConn.Close()
		return nil, err
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: upConn}
	return resp, nil
}
