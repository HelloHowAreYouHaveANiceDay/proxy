package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// doCall fetches a token for (service, label) and makes an HTTP request to targetURL
// with the token injected as the Authorization header.
// Returns the response HTTP status code and body.
func doCall(cfg ProxyConfig, service, label, method, targetURL, reqBody string) (int, string, error) {
	res, err := fetchToken(cfg, service, label)
	if err != nil {
		return 0, "", err
	}

	var bodyReader io.Reader
	if reqBody != "" {
		bodyReader = strings.NewReader(reqBody)
	}
	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return 0, "", fmt.Errorf("invalid request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+res.AccessToken)
	if reqBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("reading response body: %w", err)
	}
	return resp.StatusCode, string(b), nil
}

// runCall implements `oauthr call <service> <method> <url> [body]`.
// Fetches a short-lived access token and makes the HTTP request with it injected,
// then prints the response status and body as JSON.
func runCall(args []string) {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	label := fs.String("label", "default", "credential slot label")
	_ = fs.Parse(args)

	if fs.NArg() < 3 {
		fail("usage", "oauthr call <service> <method> <url> [body]")
	}
	service := fs.Arg(0)
	method := strings.ToUpper(fs.Arg(1))
	targetURL := fs.Arg(2)
	reqBody := ""
	if fs.NArg() > 3 {
		reqBody = fs.Arg(3)
	}

	cfg := loadConfig()
	if cfg.ControlURL == "" {
		fail("config", "OAUTHR_CONTROL_URL not set")
	}
	if cfg.InternalSecret == "" {
		fail("config", "internal_secret not set -- start `oauthr serve` in a trusted-local context or set OAUTHR_INTERNAL_SECRET")
	}
	if cfg.ProxyToken == "" && cfg.PrincipalID == "" {
		fail("config", "not enrolled -- run `oauthr init` first")
	}

	status, body, err := doCall(cfg, service, *label, method, targetURL, reqBody)
	if err != nil {
		if cpe, ok := err.(*controlPlaneError); ok {
			if cpe.kind == "not-connected" {
				fail("not-connected", fmt.Sprintf("%s -- run `oauthr connect %s`", cpe.message, service))
			}
			fail(cpe.kind, cpe.message)
		}
		fail("network", err.Error())
	}

	emit(map[string]any{
		"ok": true,
		"result": map[string]any{
			"status": status,
			"body":   body,
		},
	})
}
