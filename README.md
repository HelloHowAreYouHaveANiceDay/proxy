# proxy

A safety-preserving **credential-injecting MITM proxy**. An agent makes normal OAuth-authenticated API calls through this local proxy and **never sees the token** -- the proxy injects credentials it fetches from a remote control plane, and the durable refresh token never lands on the agent's machine.

Carved out of the [`oauthr`](https://github.com/HelloHowAreYouHaveANiceDay/oauthr) monorepo as a standalone, reusable nugget. It is **control-plane-agnostic**: point it at any compatible backend over HTTP via `OAUTHR_CONTROL_URL`.

## What it is
- A forward/CONNECT proxy that TLS-intercepts via its own CA, matches outbound host -> service, and injects `Authorization`.
- Authenticates the caller via a per-principal token in `Proxy-Authorization`.
- Holds **no durable secrets** -- fetches a fresh access token from the control plane per request (briefly cached).
- Single dependency-free Go binary (stdlib only).

## Build
```sh
go build -o proxy .   # -> ./proxy (Unix/Mac) or proxy.exe (Windows)
```
Requires Go 1.23+. No external dependencies.

## Use
```sh
export OAUTHR_CONTROL_URL=https://<your-control-plane>
export OAUTHR_INTERNAL_SECRET=<shared secret>
./proxy serve                 # start the injecting proxy
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.oauthr/ca.crt
curl https://www.googleapis.com/oauth2/v3/userinfo   # token injected; caller sends no Authorization
```

## Threat model
The provider token lives only in the (remote) control plane; the caller holds a short-lived, scoped capability, never a credential. See the `oauthr` SPEC for the full two-plane design. `--hardened` (Unix) runs the proxy as a dedicated uid so a compromised same-user agent cannot read its in-memory short-lived tokens or CA key.

## Testing
```sh
go test ./...   # in-process mock OAuth provider + mock control plane; no external services
```
