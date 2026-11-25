package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeURLWithContextRejectsOutOfScopeRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/landing", http.StatusFound)
	}))
	defer start.Close()

	ctx := WithHostScope(context.Background(), []string{"127.0.0.1"})
	if svc := probeURLWithContext(ctx, start.URL+"/start"); svc == nil || svc.StatusCode != http.StatusOK {
		t.Fatalf("same-host redirect was blocked: %+v", svc)
	}

	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://outside.invalid/secret", http.StatusFound)
	}))
	defer outside.Close()
	if svc := probeURLWithContext(ctx, outside.URL+"/start"); svc != nil {
		t.Fatalf("out-of-scope redirect was followed: %+v", svc)
	}
}

func TestScannerRedirectClientPoliciesAndExclusions(t *testing.T) {
	var excludedHits atomic.Int32
	excludedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		excludedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer excludedSrv.Close()

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	redirToExcluded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, excludedSrv.URL+"/secret", http.StatusFound)
	}))
	defer redirToExcluded.Close()

	redirToOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, okSrv.URL+"/ok", http.StatusFound)
	}))
	defer redirToOK.Close()

	redirCrossHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.invalid/landing", http.StatusFound)
	}))
	defer redirCrossHost.Close()

	ctx := WithHostScope(context.Background(), []string{"127.0.0.1"})
	ctx = WithExclusions(ctx, ParseExclusions(URLHost(excludedSrv.URL)))

	// RedirectInScope blocks redirect to an excluded host:port.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirToExcluded.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ScannerRedirectClient(5*time.Second, 5, RedirectInScope).Do(req)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("RedirectInScope to excluded host: err = %v, want ErrDestinationBlocked", err)
	}
	if excludedHits.Load() != 0 {
		t.Fatalf("excluded host was contacted %d times", excludedHits.Load())
	}

	// RedirectSameHost blocks redirect to an excluded port on the same host.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, redirToExcluded.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = ScannerRedirectClient(5*time.Second, 5, RedirectSameHost).Do(req)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("RedirectSameHost to excluded host:port: err = %v, want ErrDestinationBlocked", err)
	}
	if excludedHits.Load() != 0 {
		t.Fatalf("excluded host was contacted %d times", excludedHits.Load())
	}

	// RedirectSameHost stops at 302 for cross-host redirects.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, redirCrossHost.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = ScannerRedirectClient(5*time.Second, 5, RedirectSameHost).Do(req)
	if err != nil {
		t.Fatalf("RedirectSameHost cross-host returned unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("RedirectSameHost cross-host status = %d, want 302", resp.StatusCode)
	}

	// RedirectSameHost follows non-excluded same-host redirect.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, redirToOK.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = ScannerRedirectClient(5*time.Second, 5, RedirectSameHost).Do(req)
	if err != nil {
		t.Fatalf("RedirectSameHost same-host returned unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RedirectSameHost same-host status = %d, want 200", resp.StatusCode)
	}

	// RedirectNone never follows redirects.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, redirToOK.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = ScannerRedirectClient(5*time.Second, 5, RedirectNone).Do(req)
	if err != nil {
		t.Fatalf("RedirectNone returned unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("RedirectNone status = %d, want 302", resp.StatusCode)
	}
}

func TestDirectIPClientBlocksExcludedPinnedIPAndCIDR(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	targetAddr := srv.Listener.Addr().String()
	client := DirectIPClient(5*time.Second, targetAddr, "example.com")

	// Blocked by CIDR covering the pinned IP.
	cidrCtx := WithExclusions(context.Background(), ParseExclusions("127.0.0.0/8"))
	req, err := http.NewRequestWithContext(cidrCtx, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("DirectIPClient with excluded CIDR: err = %v, want ErrDestinationBlocked", err)
	}

	// Blocked by exact pinned host:port exclusion.
	addrCtx := WithExclusions(context.Background(), ParseExclusions(targetAddr))
	req, err = http.NewRequestWithContext(addrCtx, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = client.Do(req)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("DirectIPClient with excluded targetAddr: err = %v, want ErrDestinationBlocked", err)
	}

	// Blocked by excluded requested hostname.
	hostCtx := WithExclusions(context.Background(), ParseExclusions("blocked.example"))
	req, err = http.NewRequestWithContext(hostCtx, http.MethodGet, "http://blocked.example/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = client.Do(req)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("DirectIPClient with excluded request host: err = %v, want ErrDestinationBlocked", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("excluded DirectIPClient target was contacted %d times", hits.Load())
	}

	// Allowed when exclusions do not match either requested host or pinned IP.
	okCtx := WithExclusions(context.Background(), ParseExclusions("10.0.0.0/8"))
	req, err = http.NewRequestWithContext(okCtx, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DirectIPClient allowed target returned error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("DirectIPClient allowed target status=%d hits=%d, want 200 and 1", resp.StatusCode, hits.Load())
	}
}

func TestGuardedDialContextBlocksHostnameResolvingToExcludedCIDR(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := WithExclusions(context.Background(), ParseExclusions("127.0.0.0/8,::1/128"))
	_, err := guardedDialContext(ctx, "tcp", "localhost:80")
	if !errors.Is(err, ErrDestinationBlocked) {
		t.Fatalf("guardedDialContext(localhost:80) with loopback CIDR excluded: err = %v, want ErrDestinationBlocked", err)
	}
}

func TestCredentialClientOptionsAndDefaults(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	customCalled := false
	c := CredentialClient(
		7*time.Second,
		WithCredentialHTTP1Only(),
		WithCredentialCookieJar(jar),
		WithCredentialRedirectCheck(func(*http.Request, []*http.Request) error {
			customCalled = true
			return http.ErrUseLastResponse
		}),
	)
	if c.Timeout != 7*time.Second {
		t.Fatalf("timeout = %v, want 7s", c.Timeout)
	}
	if c.Jar != jar {
		t.Fatalf("cookie jar was not installed")
	}
	rt, ok := c.Transport.(identityRoundTripper)
	if !ok {
		t.Fatalf("transport = %T, want identityRoundTripper", c.Transport)
	}
	tr, ok := rt.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport = %T, want *http.Transport", rt.base)
	}
	if tr == guardedCredentialTransport {
		t.Fatalf("WithCredentialHTTP1Only must clone guardedCredentialTransport")
	}
	if tr.ForceAttemptHTTP2 {
		t.Fatalf("WithCredentialHTTP1Only left ForceAttemptHTTP2 enabled")
	}
	if tr.TLSNextProto == nil {
		t.Fatalf("WithCredentialHTTP1Only left TLSNextProto nil")
	}
	if err := c.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) || !customCalled {
		t.Fatalf("custom redirect check not invoked: err=%v called=%v", err, customCalled)
	}

	// Default CredentialClient shares guardedCredentialTransport and refuses redirects.
	def := CredentialClient(5 * time.Second)
	defRT, ok := def.Transport.(identityRoundTripper)
	if !ok || defRT.base != guardedCredentialTransport {
		t.Fatalf("default CredentialClient should wrap guardedCredentialTransport, got %T (%v)", def.Transport, defRT.base)
	}
	if err := def.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("default CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}
