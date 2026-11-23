package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// sharedHTTPTransport is a single, tuned transport reused by every scanner
// module. Before this, each module created its own http.Client with the default
// transport, so connections were never pooled across modules — every one of the
// tens of thousands of scan requests paid a fresh TCP + TLS handshake. Sharing
// one transport with a large idle-connection pool lets keep-alive reuse those
// connections, cutting CPU and latency dramatically without touching detection
// logic.
var baseDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

// scopeGuardedDialContext blocks a connection whose destination resolves into
// an excluded CIDR. Hostname gates only see a name, so a crawled host such as
// intranet.example.com resolving to 10.x can otherwise slip past a 10.0.0.0/8
// exclusion. The check runs at connect time on the real destination. When the
// request carries no CIDR exclusions the normal pooled dialer is used, so
// ordinary scans pay no extra lookup.
func scopeGuardedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	excl := exclusionsFromContext(ctx)
	if excl.Empty() || !excl.HasCIDRs() {
		return baseDialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if excl.ExcludesWithIPs(host, []net.IP{ip}) {
			return nil, fmt.Errorf("%w: %s is in an excluded CIDR", ErrDestinationBlocked, host)
		}
		return baseDialer.DialContext(ctx, network, addr)
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(resolved))
	for _, ia := range resolved {
		ips = append(ips, ia.IP)
	}
	if excl.ExcludesWithIPs(host, ips) {
		return nil, fmt.Errorf("%w: %s resolves into an excluded CIDR", ErrDestinationBlocked, host)
	}
	// Pin the connection to the validated addresses so DNS cannot be rebound
	// between the check and the connect.
	var lastErr error
	for _, ia := range resolved {
		conn, e := baseDialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
		if e == nil {
			return conn, nil
		}
		lastErr = e
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return baseDialer.DialContext(ctx, network, addr)
}

var baseHTTPTransport = &http.Transport{
	Proxy:       http.ProxyFromEnvironment,
	DialContext: scopeGuardedDialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          512,
	MaxIdleConnsPerHost:   16,
	MaxConnsPerHost:       32,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	// CRITICAL for coverage: bug-bounty scopes are full of dev/staging/internal
	// hosts with self-signed, expired, or hostname-mismatched TLS certs — and
	// that's exactly where the interesting bugs live. Verifying certs would make
	// every such host fail the handshake and be silently skipped (missed bugs).
	// A scanner deliberately reaches the target regardless of cert validity.
	// MinVersion TLS 1.0 so we can still talk to legacy endpoints.
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- authorized scanner must retain coverage of broken-cert staging and legacy endpoints
		MinVersion:         tls.VersionTLS10,
	},
}

// All target-facing clients use this wrapper. It applies the effective
// per-target/global bounty-program identity at the last possible point, so even
// requests created by less common scanners cannot silently omit it.
var sharedHTTPTransport http.RoundTripper = identityRoundTripper{base: baseHTTPTransport}

// newPooledClient returns an http.Client backed by the shared pooled transport.
// followRedirects=false makes it stop at the first response (what most active
// checks want, so a 302 isn't silently followed and masked).
func newPooledClient(timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{
		Timeout:   timeout,
		Transport: sharedHTTPTransport,
	}
	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}
