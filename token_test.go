package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchToken_HappyPath(t *testing.T) {
	const wantTok = "ya29.test-access-token"
	wantExpiry := time.Now().Add(time.Hour).Unix()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal/token" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Internal-Secret") != "test-secret" {
			http.Error(w, "bad secret", http.StatusUnauthorized)
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

	cfg := ProxyConfig{
		ControlURL:     srv.URL,
		InternalSecret: "test-secret",
		PrincipalID:    "p1",
	}
	res, err := fetchToken(cfg, "google", "default")
	if err != nil {
		t.Fatalf("fetchToken returned error: %v", err)
	}
	if res.AccessToken != wantTok {
		t.Errorf("access_token = %q, want %q", res.AccessToken, wantTok)
	}
	if res.ExpiresAt != wantExpiry {
		t.Errorf("expires_at = %d, want %d", res.ExpiresAt, wantExpiry)
	}
}

func TestFetchToken_NotConnected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": map[string]string{"kind": "not-connected", "message": "no credential for google"},
		})
	}))
	defer srv.Close()

	cfg := ProxyConfig{ControlURL: srv.URL, InternalSecret: "s", PrincipalID: "p1"}
	_, err := fetchToken(cfg, "google", "default")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	cpe, ok := err.(*controlPlaneError)
	if !ok {
		t.Fatalf("expected *controlPlaneError, got %T: %v", err, err)
	}
	if cpe.kind != "not-connected" {
		t.Errorf("error kind = %q, want %q", cpe.kind, "not-connected")
	}
}

func TestFetchToken_PrefersProxyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["proxy_token"] == "" {
			http.Error(w, "missing proxy_token", http.StatusBadRequest)
			return
		}
		if body["principal_id"] != "" {
			http.Error(w, "should not send principal_id when proxy_token set", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":           true,
			"access_token": "tok-via-proxy-token",
			"expires_at":   time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer srv.Close()

	cfg := ProxyConfig{
		ControlURL:     srv.URL,
		InternalSecret: "s",
		ProxyToken:     "ptoken-123",
		PrincipalID:    "p1",
	}
	res, err := fetchToken(cfg, "google", "default")
	if err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if res.AccessToken != "tok-via-proxy-token" {
		t.Errorf("access_token = %q", res.AccessToken)
	}
}
