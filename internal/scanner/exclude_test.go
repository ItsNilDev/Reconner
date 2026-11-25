package scanner

import (
	"net"
	"testing"
)

func TestExclusions(t *testing.T) {
	e := ParseExclusions("dev.example.com, *.staging.example.com, 10.0.0.0/24, https://admin.example.com/panel, 192.168.5.5")

	excluded := []string{
		"dev.example.com",              // exact
		"DEV.example.com",              // case-insensitive
		"staging.example.com",          // wildcard apex
		"api.staging.example.com",      // wildcard subdomain
		"deep.api.staging.example.com", // nested wildcard
		"admin.example.com",            // from URL
		"10.0.0.7",                     // CIDR
		"192.168.5.5",                  // exact IP
		"dev.example.com:8443",         // host:port stripped
	}
	for _, h := range excluded {
		if !e.Excludes(h) {
			t.Errorf("%q should be excluded", h)
		}
	}

	kept := []string{
		"example.com",            // apex not excluded by a subdomain rule
		"www.example.com",        // unrelated host
		"staging.example.org",    // different registrable
		"10.0.1.7",               // outside the /24
		"notstaging.example.com", // must not match the *.staging suffix loosely
	}
	for _, h := range kept {
		if e.Excludes(h) {
			t.Errorf("%q should NOT be excluded", h)
		}
	}

	// Network-side: excluded IPs are dropped from an expanded scope.
	ips := []string{"10.0.0.1", "10.0.0.99", "192.168.5.5", "8.8.8.8"}
	kept, dropped := FilterExcludedIPs(ips, e)
	if dropped != 3 { // 10.0.0.1, 10.0.0.99 (in /24), 192.168.5.5
		t.Errorf("dropped=%d want 3 (kept=%v)", dropped, kept)
	}
	if len(kept) != 1 || kept[0] != "8.8.8.8" {
		t.Errorf("kept=%v want [8.8.8.8]", kept)
	}
	if _, d := FilterExcludedIPs(ips, ParseExclusions("")); d != 0 {
		t.Errorf("no exclusions must drop nothing, dropped=%d", d)
	}

	if !ParseExclusions("").Empty() {
		t.Error("empty exclude string must yield an Empty set")
	}
	if ParseExclusions("a.com").Excludes("b.com") {
		t.Error("unrelated host must not be excluded")
	}
}

func TestExclusionSyntaxNormalization(t *testing.T) {
	t.Run("leading dot stays a suffix rule", func(t *testing.T) {
		e := ParseExclusions(".dev.example.com")
		for _, h := range []string{"dev.example.com", "api.dev.example.com", "DEV.EXAMPLE.COM."} {
			if !e.Excludes(h) {
				t.Errorf("%q should be excluded", h)
			}
		}
		if e.Excludes("example.com") || e.Excludes("notdev.example.com") {
			t.Error("leading-dot rule must not match unrelated hosts")
		}
	})

	t.Run("bare host:port blocks only that destination", func(t *testing.T) {
		e := ParseExclusions("admin.example.com:8443")
		if !e.Excludes("admin.example.com:8443") {
			t.Error("host:port rule must match the exact destination")
		}
		if !e.Excludes("admin.example.com") {
			t.Error("unknown port must be blocked conservatively")
		}
		if e.Excludes("admin.example.com:443") {
			t.Error("a different known port must not be blocked")
		}
		if e.Excludes("example.com:8443") {
			t.Error("a different host must not be blocked")
		}
	})

	t.Run("bracketed IPv6 and port", func(t *testing.T) {
		e := ParseExclusions("[2001:db8::1]:8443")
		if !e.Excludes("[2001:db8::1]:8443") {
			t.Error("bracketed IPv6 endpoint must be excluded")
		}
		v6 := ParseExclusions("2001:db8::2")
		if !v6.Excludes("2001:db8::2") {
			t.Error("bare IPv6 must be excluded")
		}
	})

	t.Run("URL rule keeps host-wide meaning", func(t *testing.T) {
		e := ParseExclusions("https://admin.example.com/panel")
		if !e.Excludes("admin.example.com:443") || !e.Excludes("admin.example.com/other") {
			t.Error("a URL rule must exclude the whole host")
		}
	})

	t.Run("CIDR evaluates resolved addresses", func(t *testing.T) {
		e := ParseExclusions("10.0.0.0/24")
		ip := []net.IP{net.ParseIP("10.0.0.7")}
		if !e.ExcludesWithIPs("host.example.com", ip) {
			t.Error("hostname resolving into the CIDR must be excluded")
		}
		if e.ExcludesWithIPs("host.example.com", []net.IP{net.ParseIP("10.0.1.7")}) {
			t.Error("hostname outside the CIDR must not be excluded")
		}
	})
}

func TestExclusionSchemelessPathsAndWildcards(t *testing.T) {
	set := ParseExclusions("admin.example.com/panel\n*.staging.example.com/*")
	if !set.Excludes("admin.example.com") {
		t.Error("schemeless path rule must exclude the whole host")
	}
	if !set.Excludes("api.staging.example.com") {
		t.Error("wildcard path rule must exclude descendants")
	}
}

func TestExclusionBracketedIPv6(t *testing.T) {
	set := ParseExclusions("[2001:db8::1]")
	if !set.Excludes("2001:db8::1") {
		t.Error("bracketed IPv6 rule must exclude the literal host")
	}
}
