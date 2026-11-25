package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
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
	if excl.Empty() {
		return baseDialer.DialContext(ctx, network, addr)
	}
	if excl.Excludes(addr) {
		return nil, fmt.Errorf("%w: %s is excluded", ErrDestinationBlocked, addr)
	}
	if !excl.HasCIDRs() {
		return baseDialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if excl.ExcludesWithIPs(addr, []net.IP{ip}) {
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
	if excl.ExcludesWithIPs(addr, ips) {
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
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           scopeGuardedDialContext,
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

// RedirectPolicy controls how ScannerRedirectClient handles HTTP redirects.
type RedirectPolicy int

const (
	RedirectNone RedirectPolicy = iota
	RedirectSameHost
	RedirectInScope
)

func noRedirectPolicy(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func normalizeRedirectHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// ScannerClient returns an http.Client backed by sharedHTTPTransport that does
// not follow redirects.
func ScannerClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     sharedHTTPTransport,
		Timeout:       timeout,
		CheckRedirect: noRedirectPolicy,
	}
}

// ScannerRedirectClient returns an http.Client backed by sharedHTTPTransport
// that enforces maxHops and the given RedirectPolicy on every redirect hop.
func ScannerRedirectClient(timeout time.Duration, maxHops int, policy RedirectPolicy) *http.Client {
	if policy == RedirectNone {
		return ScannerClient(timeout)
	}
	return &http.Client{
		Transport: sharedHTTPTransport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHops {
				return http.ErrUseLastResponse
			}
			switch policy {
			case RedirectSameHost:
				if len(via) > 0 && normalizeRedirectHost(req.URL.Hostname()) != normalizeRedirectHost(via[0].URL.Hostname()) {
					return http.ErrUseLastResponse
				}
				if hostExcluded(req.Context(), URLHost(req.URL.String())) {
					return fmt.Errorf("%w: redirect to %s is excluded", ErrDestinationBlocked, req.URL.Host)
				}
				return nil
			case RedirectInScope:
				if !urlHostInScope(req.Context(), req.URL.String()) {
					return fmt.Errorf("%w: redirect to %s is outside scope", ErrDestinationBlocked, req.URL.Host)
				}
				return nil
			default:
				return http.ErrUseLastResponse
			}
		},
	}
}

// DirectIPClient returns a non-redirecting http.Client that dials targetAddr
// directly (optionally overriding TLS SNI with serverName) while still
// enforcing context exclusions against both the requested address and the
// pinned target address (including CIDR rules) and applying request identity.
func DirectIPClient(timeout time.Duration, targetAddr, serverName string) *http.Client {
	tr := baseHTTPTransport.Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if serverName != "" {
		var tlsCfg *tls.Config
		if tr.TLSClientConfig != nil {
			tlsCfg = tr.TLSClientConfig.Clone()
		} else {
			tlsCfg = &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- authorized scanner must retain coverage of broken-cert staging and legacy endpoints
				MinVersion:         tls.VersionTLS10,
			}
		}
		tlsCfg.ServerName = serverName
		tr.TLSClientConfig = tlsCfg
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialAddr := targetAddr
		if dialAddr == "" {
			dialAddr = addr
		}
		excl := exclusionsFromContext(ctx)
		if !excl.Empty() {
			if excl.Excludes(addr) {
				return nil, fmt.Errorf("%w: %s is excluded", ErrDestinationBlocked, addr)
			}
			if excl.Excludes(dialAddr) {
				return nil, fmt.Errorf("%w: %s is excluded", ErrDestinationBlocked, dialAddr)
			}
			targetHost, targetPort, splitErr := net.SplitHostPort(dialAddr)
			if splitErr != nil {
				targetHost = strings.Trim(dialAddr, "[]")
			}
			if ip := net.ParseIP(targetHost); ip != nil {
				if excl.ExcludesWithIPs(dialAddr, []net.IP{ip}) {
					return nil, fmt.Errorf("%w: %s is in an excluded CIDR", ErrDestinationBlocked, targetHost)
				}
			} else if targetHost != "" && excl.HasCIDRs() {
				resolved, err := net.DefaultResolver.LookupIPAddr(ctx, targetHost)
				if err != nil {
					return nil, err
				}
				ips := make([]net.IP, 0, len(resolved))
				for _, ia := range resolved {
					ips = append(ips, ia.IP)
				}
				if excl.ExcludesWithIPs(dialAddr, ips) {
					return nil, fmt.Errorf("%w: %s resolves into an excluded CIDR", ErrDestinationBlocked, targetHost)
				}
				if splitErr == nil {
					var lastErr error
					for _, ia := range resolved {
						conn, e := baseDialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), targetPort))
						if e == nil {
							return conn, nil
						}
						lastErr = e
					}
					if lastErr != nil {
						return nil, lastErr
					}
				}
			}
		}
		return baseDialer.DialContext(ctx, network, dialAddr)
	}
	return &http.Client{
		Transport:     identityRoundTripper{base: tr},
		Timeout:       timeout,
		CheckRedirect: noRedirectPolicy,
	}
}

// externalHTTPTransport is used for third-party APIs (passive intel, secret
// verification, etc.) with standard verified TLS, no target request identity,
// and no target exclusions.
var externalHTTPTransport = &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	DialContext:         baseDialer.DialContext,
	ForceAttemptHTTP2:   true,
	MaxIdleConns:        64,
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

// ExternalClient returns an http.Client backed by externalHTTPTransport for
// third-party API calls.
func ExternalClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: externalHTTPTransport,
		Timeout:   timeout,
	}
}

// ScopedDialContext dials a raw network connection while enforcing context
// exclusions and CIDR pinning.
func ScopedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return scopeGuardedDialContext(ctx, network, addr)
}
