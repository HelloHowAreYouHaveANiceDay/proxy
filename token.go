package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
)

// controlPlaneError carries the kind+message from a not-ok control plane response.
type controlPlaneError struct {
	kind    string
	message string
}

func (e *controlPlaneError) Error() string { return e.kind + ": " + e.message }

// tokenResult holds the fields returned by a successful /v1/internal/token call.
type tokenResult struct {
	AccessToken string
	ExpiresAt   int64
}

// fetchToken calls POST /v1/internal/token on the control plane.
// cfg must have ControlURL + InternalSecret + (ProxyToken or PrincipalID) set.
// The internal_secret never leaves the trusted-local context.
func fetchToken(cfg ProxyConfig, service, label string) (*tokenResult, error) {
	reqBody := map[string]string{"service": service, "label": label}
	if cfg.ProxyToken != "" {
		reqBody["proxy_token"] = cfg.ProxyToken
	} else {
		reqBody["principal_id"] = cfg.PrincipalID
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest(http.MethodPost, cfg.ControlURL+"/v1/internal/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", cfg.InternalSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /v1/internal/token: %w", err)
	}
	defer resp.Body.Close()

	var tr struct {
		OK          bool   `json:"ok"`
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
		Error       struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !tr.OK {
		return nil, &controlPlaneError{kind: tr.Error.Kind, message: tr.Error.Message}
	}
	return &tokenResult{AccessToken: tr.AccessToken, ExpiresAt: tr.ExpiresAt}, nil
}

// runToken implements `oauthr token <service> [--label <label>]`.
// Fetches a short-lived access token via the trusted-local internal path and emits it as JSON.
// Requires internal_secret in config (sidecar/trusted-local context); agents never hold it.
func runToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	label := fs.String("label", "default", "credential slot label")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fail("usage", "oauthr token <service> [--label <label>]")
	}
	service := fs.Arg(0)

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

	res, err := fetchToken(cfg, service, *label)
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
			"access_token": res.AccessToken,
			"expires_at":   res.ExpiresAt,
			"service":      service,
			"label":        *label,
		},
	})
}
