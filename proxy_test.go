package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGetTokenFlat pins the control-plane wire format: flat envelope with access_token and
// expires_at at the top level (not nested under "result").  Regressions here surface immediately.
func TestGetTokenFlat(t *testing.T) {
	const wantTok = "ya29.test-access-token"
	wantExpiry := time.Now().Add(time.Hour).Unix()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal/token" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":           true,
			"access_token": wantTok,
			"expires_at":   wantExpiry,
		})
	}))
	defer srv.Close()

	p := newProxy(ProxyConfig{
		ControlURL:     srv.URL,
		InternalSecret: "secret",
		PrincipalID:    "p1",
	}, nil)

	got, err := p.getToken("google", "default")
	if err != nil {
		t.Fatalf("getToken returned error: %v", err)
	}
	if got != wantTok {
		t.Errorf("access_token = %q, want %q", got, wantTok)
	}
}

// TestGetTokenCached verifies the in-process token cache avoids a second control-plane call.
func TestGetTokenCached(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/v1/internal/services" {
			// Respond to the background service-pattern refresher; don't count it as a token call.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "services": []interface{}{}})
			return
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":           true,
			"access_token": "cached-tok",
			"expires_at":   time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer srv.Close()

	p := newProxy(ProxyConfig{ControlURL: srv.URL, PrincipalID: "p1"}, nil)

	if _, err := p.getToken("google", "default"); err != nil {
		t.Fatalf("first getToken: %v", err)
	}
	if _, err := p.getToken("google", "default"); err != nil {
		t.Fatalf("second getToken: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 control-plane call, got %d", calls)
	}
}

// TestGetTokenControlPlaneError verifies that a not-ok response propagates as an error.
func TestGetTokenControlPlaneError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": map[string]string{"kind": "not-connected", "message": "no credential for this slot"},
		})
	}))
	defer srv.Close()

	p := newProxy(ProxyConfig{ControlURL: srv.URL, PrincipalID: "p1"}, nil)

	_, err := p.getToken("google", "default")
	if err == nil {
		t.Fatal("expected error from not-ok response, got nil")
	}
}

// TestMatchServiceBuiltin verifies that builtin patterns cover all registered providers,
// including wildcard patterns for variable-host providers (Salesforce, Shopify).
func TestMatchServiceBuiltin(t *testing.T) {
	p := newProxy(ProxyConfig{}, nil)
	cases := []struct {
		host    string
		service string
	}{
		// Google
		{"www.googleapis.com:443", "google"},
		{"oauth2.googleapis.com:443", "google"},
		{"accounts.google.com:443", "google"},
		// Dropbox
		{"api.dropboxapi.com:443", "dropbox"},
		// Box
		{"api.box.com:443", "box"},
		// Salesforce (variable per-org instance_url -- wildcard covers all orgs)
		{"myorg.salesforce.com:443", "salesforce"},
		{"myorg.my.salesforce.com:443", "salesforce"},
		{"sandbox.salesforce.com:443", "salesforce"},
		// HubSpot
		{"api.hubapi.com:443", "hubspot"},
		// Stripe
		{"api.stripe.com:443", "stripe"},
		// Discord
		{"discord.com:443", "discord"},
		// Zoom
		{"api.zoom.us:443", "zoom"},
		// X (Twitter)
		{"api.twitter.com:443", "x"},
		// Figma
		{"api.figma.com:443", "figma"},
		// Shopify (variable per-merchant shop domain -- wildcard covers all shops)
		{"myshop.myshopify.com:443", "shopify"},
		{"another-store.myshopify.com:443", "shopify"},
		// Unknown host -- should return empty string (pass-through)
		{"unknown.example.com:443", ""},
	}
	for _, tc := range cases {
		got := p.matchService(tc.host)
		if got != tc.service {
			t.Errorf("matchService(%q) = %q, want %q", tc.host, got, tc.service)
		}
	}
}

// TestRefreshServicePatterns verifies that the proxy fetches host_patterns from the control plane
// and uses them in matchService, enabling new services to work without a proxy rebuild.
func TestRefreshServicePatterns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal/services" || r.Method != http.MethodGet {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"services": []map[string]string{
				{"service": "acme", "host_patterns": "api.acme.example.com *.acme.example.com"},
				{"service": "beta", "host_patterns": "api.beta.test"},
			},
		})
	}))
	defer srv.Close()

	p := newProxy(ProxyConfig{
		ControlURL:     srv.URL,
		InternalSecret: "secret",
		PrincipalID:    "p1",
	}, nil)

	// newProxy launches the refresher goroutine; call directly to avoid timing dependency.
	p.refreshServicePatterns()

	cases := []struct {
		host    string
		service string
	}{
		{"api.acme.example.com:443", "acme"},
		{"sub.acme.example.com:443", "acme"},
		{"api.beta.test:443", "beta"},
		// builtin still works
		{"api.stripe.com:443", "stripe"},
		// unknown
		{"unknown.example.com:443", ""},
	}
	for _, tc := range cases {
		got := p.matchService(tc.host)
		if got != tc.service {
			t.Errorf("matchService(%q) = %q, want %q", tc.host, got, tc.service)
		}
	}
}

// TestExtractLabel verifies that Proxy-Authorization: Basic base64(label:) correctly
// extracts the label. This is the format sent by HTTP clients that use
// HTTPS_PROXY=http://label:@proxy:port (nanoclaw drop-in swap pattern).
func TestExtractLabel(t *testing.T) {
	basicCred := func(user string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"))
	}

	cases := []struct {
		name    string
		header  string
		want    string
	}{
		{"no header", "", "default"},
		{"default label explicit", basicCred("default"), "default"},
		{"custom label", basicCred("nanoclaw-a"), "nanoclaw-a"},
		{"URL-credential style (user:empty-pass)", basicCred("myagent"), "myagent"},
		{"malformed non-basic", "Bearer sometoken", "default"},
		{"empty username falls back", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(":"))), "default"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodConnect, "https://api.example.com:443", nil)
			if tc.header != "" {
				r.Header.Set("Proxy-Authorization", tc.header)
			}
			got := extractLabel(r)
			if got != tc.want {
				t.Errorf("extractLabel = %q, want %q", got, tc.want)
			}
		})
	}
}
