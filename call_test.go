package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDoCall_HappyPath(t *testing.T) {
	const wantTok = "ya29.call-test-token"

	controlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/internal/token" {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":           true,
			"access_token": wantTok,
			"expires_at":   time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer controlSrv.Close()

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wantTok {
			http.Error(w, "missing or wrong Authorization", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"email": "user@example.com"})
	}))
	defer targetSrv.Close()

	cfg := ProxyConfig{
		ControlURL:     controlSrv.URL,
		InternalSecret: "test-secret",
		PrincipalID:    "p1",
	}
	status, body, err := doCall(cfg, "google", "default", "GET", targetSrv.URL+"/userinfo", "")
	if err != nil {
		t.Fatalf("doCall: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", status, body)
	}
	if body == "" {
		t.Error("expected non-empty response body")
	}
}

func TestDoCall_TokenFetchFails(t *testing.T) {
	controlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": map[string]string{"kind": "not-connected", "message": "no credential for google"},
		})
	}))
	defer controlSrv.Close()

	cfg := ProxyConfig{ControlURL: controlSrv.URL, InternalSecret: "s", PrincipalID: "p1"}
	_, _, err := doCall(cfg, "google", "default", "GET", "http://example.com", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	cpe, ok := err.(*controlPlaneError)
	if !ok {
		t.Fatalf("expected *controlPlaneError, got %T: %v", err, err)
	}
	if cpe.kind != "not-connected" {
		t.Errorf("kind = %q, want not-connected", cpe.kind)
	}
}

func TestDoCall_PostWithBody(t *testing.T) {
	const wantTok = "ya29.post-token"

	controlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":           true,
			"access_token": wantTok,
			"expires_at":   time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer controlSrv.Close()

	var gotMethod, gotBody, gotContentType string
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		w.WriteHeader(http.StatusCreated)
	}))
	defer targetSrv.Close()

	cfg := ProxyConfig{ControlURL: controlSrv.URL, InternalSecret: "s", PrincipalID: "p1"}
	status, _, err := doCall(cfg, "google", "default", "POST", targetSrv.URL+"/data", `{"key":"val"}`)
	if err != nil {
		t.Fatalf("doCall: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want 201", status)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotBody != `{"key":"val"}` {
		t.Errorf("body = %q, want {\"key\":\"val\"}", gotBody)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
}
