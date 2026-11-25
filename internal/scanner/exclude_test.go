package scanner

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/recon-platform/internal/database"
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

func TestParseManualExclusionPatterns(t *testing.T) {
	raw := "  admin.example.com, *.staging.example.com;\n10.0.0.0/8\tadmin.example.com\r\n  #bounty:p1|ignored.test  "
	got := ParseManualExclusionPatterns(raw)
	want := []string{
		"admin.example.com",
		"*.staging.example.com",
		"10.0.0.0/8",
		"#bounty:p1|ignored.test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseManualExclusionPatterns = %v, want %v", got, want)
	}
	if got := ParseManualExclusionPatterns(" , \n\t\r; "); len(got) != 0 {
		t.Fatalf("expected empty slice for delimiter-only input, got %v", got)
	}
}

func TestCompileExclusions(t *testing.T) {
	set := CompileExclusions([]string{
		"https://admin.example.com:8443/panel",
		"10.20.0.0/16",
		"portal.example.com/secret",
		"*.dev.example.com",
		".qa.example.com",
		"api.example.com:9000",
		"[2001:db8::1]:8443",
		"exact.example.com",
		"#bounty:p1|should-not-parse.example.com",
		"   ",
	})
	for _, host := range []string{
		"admin.example.com",
		"admin.example.com:443",
		"10.20.1.5",
		"portal.example.com",
		"dev.example.com",
		"sub.dev.example.com",
		"qa.example.com",
		"sub.qa.example.com",
		"api.example.com:9000",
		"[2001:db8::1]:8443",
		"exact.example.com",
	} {
		if !set.Excludes(host) {
			t.Errorf("expected %q to be excluded", host)
		}
	}
	for _, host := range []string{
		"api.example.com:443",
		"should-not-parse.example.com",
		"app.example.com",
	} {
		if set.Excludes(host) {
			t.Errorf("expected %q not to be excluded", host)
		}
	}
}

func TestLoadExclusionsEFromTable(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "exclusions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1', 'example.test'), ('t2', 'other.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO target_exclusions (id, target_id, source, program_id, pattern) VALUES
		('e1', 't1', 'manual', '', 'admin.example.test'),
		('e2', 't1', 'bounty', 'prog-1', '*.staging.example.test'),
		('e3', 't2', 'manual', '', 'other-only.example.test')`); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	set, err := LoadExclusionsE(ctx, db, "t1")
	if err != nil {
		t.Fatalf("LoadExclusionsE failed: %v", err)
	}
	if !set.Excludes("admin.example.test") {
		t.Error("expected manual pattern from target_exclusions to be excluded")
	}
	if !set.Excludes("api.staging.example.test") {
		t.Error("expected bounty pattern from target_exclusions to be excluded")
	}
	if set.Excludes("other-only.example.test") {
		t.Error("exclusion from another target must not bleed into t1")
	}

	if err := ReplaceManualExclusionsTx(ctx, db, "t1", "new-manual.example.test, 192.0.2.0/24"); err != nil {
		t.Fatalf("ReplaceManualExclusionsTx failed: %v", err)
	}
	set, err = LoadExclusionsE(ctx, db, "t1")
	if err != nil {
		t.Fatalf("LoadExclusionsE after replace failed: %v", err)
	}
	if set.Excludes("admin.example.test") {
		t.Error("replaced manual pattern should no longer be excluded")
	}
	if !set.Excludes("new-manual.example.test") || !set.Excludes("192.0.2.9") {
		t.Error("new manual patterns should be excluded")
	}
	if !set.Excludes("api.staging.example.test") {
		t.Error("bounty pattern must survive ReplaceManualExclusionsTx")
	}

	if _, err := LoadExclusionsE(ctx, nil, "t1"); err == nil {
		t.Error("expected error when db is nil")
	}
}

func TestCompileExclusionsAnnotatedBountyRulesAndTrailingDotPort(t *testing.T) {
	set := CompileExclusions([]string{
		"*.staging.example.test (do not test)",
		"10.0.0.0/8 (internal)",
		"excluded.example.com",
	})
	if !set.Excludes("api.staging.example.test") {
		t.Error("annotated wildcard deny rule must match descendant")
	}
	if !set.Excludes("10.20.30.40") {
		t.Error("annotated CIDR deny rule must match IP in range")
	}
	if !set.Excludes("excluded.example.com.:443") {
		t.Error("trailing-dot FQDN with port must not bypass exclusion")
	}
	if !set.Excludes("api.staging.example.test.:8443") {
		t.Error("trailing-dot descendant FQDN with port must not bypass wildcard exclusion")
	}
}
