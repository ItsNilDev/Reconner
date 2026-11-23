package scanner

import (
	"context"
	"testing"
)

func TestIsWildcardScopePattern(t *testing.T) {
	cases := map[string]bool{
		"*.example.com": true,
		"*":             true,
		"example.*":     true,
		"example.com":   false,
		"a.example.com": false,
		"":              false,
	}
	for raw, want := range cases {
		if got := IsWildcardScopePattern(raw); got != want {
			t.Errorf("IsWildcardScopePattern(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestNoHostScopeBlocksEveryHost(t *testing.T) {
	ctx := WithNoHostScope(context.Background())
	if hostScopeSet(ctx) == nil {
		t.Fatal("explicit empty host scope must be non-nil")
	}
	for _, host := range []string{"play.google.com", "example.com", "anything.test"} {
		if hostInScope(ctx, host) {
			t.Errorf("expected %q out of scope", host)
		}
	}
	if got := filterURLsByHostScope(ctx, []string{"https://example.com/a"}); len(got) != 0 {
		t.Errorf("filterURLsByHostScope=%v, want empty", got)
	}
}

// TestStrictWatchScopeHonorsProgramBoundary proves that a breadth round uses
// the eligibility matcher: an exact asset covers only its apex, while a wildcard
// covers descendants but not the apex itself.
func TestStrictWatchScopeHonorsProgramBoundary(t *testing.T) {
	entries := []WatchScopeEntry{
		{host: "exact.example.com"},
		{host: "wild.example.org", IsWildcard: true},
	}
	ctx := WithStrictWatchScope(context.Background(), entries)

	cases := map[string]bool{
		"exact.example.com":     true,
		"a.exact.example.com":   false,
		"wild.example.org":      false,
		"a.wild.example.org":    true,
		"a.b.wild.example.org":  true,
		"unrelated.example.net": false,
	}
	for host, want := range cases {
		if got := hostInScope(ctx, host); got != want {
			t.Errorf("hostInScope(%q)=%v, want %v", host, got, want)
		}
	}
}

func TestHostScopeAcceptsURLsAndSubdomains(t *testing.T) {
	ctx := WithHostScope(context.Background(), []string{"https://App.Example.com/account", "*.example.org"})
	for _, host := range []string{"app.example.com", "api.app.example.com", "www.example.org"} {
		if !hostInScope(ctx, host) {
			t.Errorf("expected %q in scope", host)
		}
	}
	for _, host := range []string{"evil-example.com", "example.net"} {
		if hostInScope(ctx, host) {
			t.Errorf("expected %q out of scope", host)
		}
	}
}
