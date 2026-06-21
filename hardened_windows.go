//go:build windows

package main

// hardenedContextOK always returns (false, reason) on Windows.
// Windows isolation primitives (AppContainer, Job Objects, separate user accounts)
// require administrator bootstrapping that is not yet supported by oauthr.
// On Windows, use nanoclaw (container) for equivalent proxy isolation:
//
//	nanoclaw puts the agent in a container; the proxy runs on the host outside it.
//	Set HTTP_PROXY=<nanoclaw-proxy> and trust the nanoclaw CA instead of --hardened.
func hardenedContextOK() (bool, string) {
	return false, "--hardened is not supported on Windows.\n" +
		"For equivalent proxy isolation on Windows use nanoclaw (container mode):\n" +
		"  the agent runs inside the container; the oauthr proxy runs on the host.\n" +
		"Set HTTP_PROXY=<nanoclaw-proxy-addr> and trust the nanoclaw CA cert in the container.\n" +
		"See docs/nanoclaw.md for setup instructions."
}
