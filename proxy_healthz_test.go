package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProxy_Healthz guards the discovery contract: a direct GET /healthz must return 200.
// Drivers (driver.go) treat a non-200 /healthz as a stale instance and DELETE the discovery
// file, so without this the proxy path is never usable. Regression: the handler was missing
// and GET /healthz was proxied to itself -> 502.
func TestProxy_Healthz(t *testing.T) {
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newProxy(ProxyConfig{}, ca))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("GET /healthz body: want {\"ok\":true}, got %q", body)
	}
}

// TestProxy_MatchService_Linear guards that api.linear.app maps to the linear service so the
// proxy injects auth for bim-linear's GraphQL calls. Regression: linear was absent from the
// builtin pattern list, so matchService returned "" and no token was injected (Linear 401).
func TestProxy_MatchService_Linear(t *testing.T) {
	p := newProxy(ProxyConfig{}, &CA{})
	for _, host := range []string{"api.linear.app", "api.linear.app:443"} {
		if got := p.matchService(host); got != "linear" {
			t.Errorf("matchService(%q) = %q, want linear", host, got)
		}
	}
}
