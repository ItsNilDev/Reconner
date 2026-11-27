package scanner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/database"
)

func TestNormalizeScopeIdentifier(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"Example.COM.", "example.com", true},
		{"https://Example.com/", "example.com", true},
		{"*.Example.COM", "example.com", true},
		{"example.com:8443", "example.com", true},  // port stripped for matching
		{"https://example.com/api/v1/", "", false}, // path-scoped: not landable
		{"example.com/api", "", false},
		{"*example.com", "", false},      // missing dot
		{"sub.*.example.com", "", false}, // mid-domain glob
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeScopeIdentifier(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Errorf("normalizeScopeIdentifier(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeWatchHost(t *testing.T) {
	cases := []struct {
		raw       string
		wantValue string
		wantHost  string
		wantPort  string
		ok        bool
	}{
		{"Sub.Example.COM.", "sub.example.com", "sub.example.com", "", true},
		{"https://sub.example.com/", "sub.example.com", "sub.example.com", "", true},
		{"example.com:80", "example.com", "example.com", "80", true},
		{"example.com:8443", "example.com:8443", "example.com", "8443", true},
		{"example.com:443", "example.com", "example.com", "443", true},
	}
	for _, tc := range cases {
		got, ok := normalizeWatchHost(tc.raw)
		if ok != tc.ok || got.Value != tc.wantValue || got.Host != tc.wantHost || got.Port != tc.wantPort {
			t.Errorf("normalizeWatchHost(%q) = (%+v,%v), want value=%q host=%q port=%q ok=%v",
				tc.raw, got, ok, tc.wantValue, tc.wantHost, tc.wantPort, tc.ok)
		}
	}
}

func TestMatchWatchHost(t *testing.T) {
	entries := []WatchScopeEntry{
		{Identifier: "*.example.com", IsWildcard: true, host: "example.com"},
		{Identifier: "exact.test", host: "exact.test"},
	}
	host := func(s string) WatchScopeHost { h, _ := normalizeWatchHost(s); return h }

	cases := []struct {
		name  string
		query string
		want  string // matched identifier, "" for no match
	}{
		{"wildcard one level", "a.example.com", "*.example.com"},
		{"wildcard two levels", "a.b.example.com", "*.example.com"},
		{"wildcard does not match apex", "example.com", ""},
		{"wildcard does not match other base", "a.notexample.com", ""},
		{"exact match", "exact.test", "exact.test"},
		{"exact wins over wildcard", "exact.example.com", "*.example.com"},
		{"port does not block match", "a.example.com:8443", "*.example.com"},
		{"unmatched", "random.org", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchWatchHost(entries, host(tc.query))
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected match: %+v", got)
				}
				return
			}
			if !ok || got.Identifier != tc.want {
				t.Fatalf("matchWatchHost(%q) = (%+v,%v), want identifier %q", tc.query, got, ok, tc.want)
			}
		})
	}
}

func TestNormalizeScopeIdentifierRejectsPunycodeHost(t *testing.T) {
	got, ok := normalizeScopeIdentifier("BÜCHER.example")
	if !ok || got != "xn--bcher-kva.example" {
		t.Fatalf("punycode = (%q,%v), want xn--bcher-kva.example", got, ok)
	}
}

func TestLoadWatchEligibleScopeSkipsNonWebAssets(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','acme.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('program-1','hackerone','p1','acme','Acme')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project_programs(target_id,program_id) VALUES('target-1','program-1')`); err != nil {
		t.Fatal(err)
	}
	assets := []struct{ id, identifier, assetType string }{
		{"a-store", "https://play.google.com/store/apps/details?id=com.example", "app_store"},
		{"a-android", "com.example.app", "android"},
		{"a-note", "Third Party Marketplace Apps", "other"},
		{"a-ip", "192.0.2.10", "ip"},
		{"a-web", "*.acme.test", "wildcard"},
	}
	for _, a := range assets {
		if _, err := db.Exec(`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type) VALUES(?,?,'ext-?' || ?,?,?)`,
			a.id, "program-1", a.id, a.identifier, a.assetType); err != nil {
			t.Fatal(err)
		}
	}
	entries, linked, err := LoadWatchEligibleScope(ctx, db, "target-1")
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("project must report a linked program")
	}
	if len(entries) != 1 || entries[0].Identifier != "*.acme.test" {
		t.Fatalf("eligible scope=%+v, want only *.acme.test", entries)
	}
}

func TestNormalizeSubdomainWildcardApexAndIdentifier(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"*.example.com", "example.com", true},
		{"*.Example.COM.", "example.com", true},
		{"https://*.example.com/", "example.com", true},
		{"http://*.sub.example.com:8443/", "sub.example.com", true},
		{"*.example.com:8443", "example.com", true},
		{"*.BÜCHER.example", "xn--bcher-kva.example", true},
		{"example.com", "", false},
		{"https://example.com/", "", false},
		{"https://example.com/*", "", false},
		{"*.example.com/*", "", false},
		{"https://*.example.com/api", "", false},
		{"sub.*.example.com", "", false},
		{"*.*.example.com", "", false},
		{"*example.com", "", false},
		{"*.192.0.2.1", "", false},
		{"*.[::1]", "", false},
		{"*.", "", false},
		{"*..", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeSubdomainWildcardApex(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeSubdomainWildcardApex(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
		if isWild := IsSubdomainWildcardIdentifier(tc.raw); isWild != tc.ok {
			t.Errorf("IsSubdomainWildcardIdentifier(%q) = %v, want %v", tc.raw, isWild, tc.ok)
		}
	}
}

func TestNormalizeWatchScopeBareHost(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM.", "example.com", true},
		{"https://example.com/", "example.com", true},
		{"https://example.com:8443/", "example.com", true},
		{"example.com:8443", "example.com", true},
		{"BÜCHER.example", "xn--bcher-kva.example", true},
		{"*.example.com", "", false},
		{"https://*.example.com/", "", false},
		{"https://example.com/*", "", false},
		{"https://example.com/api", "", false},
		{"192.0.2.1", "", false},
		{"[::1]", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeWatchScopeBareHost(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeWatchScopeBareHost(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestWildcardRootMatchesWatchScope(t *testing.T) {
	entries := []WatchScopeEntry{
		{ProgramID: "p-wild", AssetID: "a-wild", Identifier: "*.example.com", IsWildcard: true, host: "example.com"},
		{ProgramID: "p-exact", AssetID: "a-exact", Identifier: "exact.test", IsWildcard: false, host: "exact.test"},
	}
	if got := entries[0].NormalizedHost(); got != "example.com" {
		t.Fatalf("NormalizedHost() = %q, want example.com", got)
	}
	if narrowed := entries[0].WithNormalizedHost("Sub.Example.COM."); narrowed.NormalizedHost() != "sub.example.com" || !narrowed.IsWildcard || narrowed.ProgramID != "p-wild" {
		t.Fatalf("WithNormalizedHost() = %+v, want host=sub.example.com wildcard=true program=p-wild", narrowed)
	}

	cases := []struct {
		name    string
		raw     string
		wantOK  bool
		wantPID string
		wantAID string
	}{
		{"exact wildcard", "*.example.com", true, "p-wild", "a-wild"},
		{"scheme wildcard", "https://*.example.com/", true, "p-wild", "a-wild"},
		{"nested wildcard", "*.sub.example.com", true, "p-wild", "a-wild"},
		{"deep nested scheme wildcard", "https://*.deep.sub.example.com:8443/", true, "p-wild", "a-wild"},
		{"rejects bare apex", "example.com", false, "", ""},
		{"rejects path wildcard", "https://example.com/*", false, "", ""},
		{"rejects mid glob", "sub.*.example.com", false, "", ""},
		{"rejects ip wildcard", "*.192.0.2.1", false, "", ""},
		{"rejects non-wildcard entry", "*.exact.test", false, "", ""},
		{"rejects suffix confusion", "*.notexample.com", false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, aid, ok := WildcardRootMatchesWatchScope(entries, tc.raw)
			if ok != tc.wantOK || pid != tc.wantPID || aid != tc.wantAID {
				t.Fatalf("WildcardRootMatchesWatchScope(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.raw, pid, aid, ok, tc.wantPID, tc.wantAID, tc.wantOK)
			}
		})
	}
}

func TestLoadWatchEligibleScopeInfersWildcardWhenFlagZero(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope-wild.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','acme.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('program-1','hackerone','p1','acme','Acme')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project_programs(target_id,program_id) VALUES('target-1','program-1')`); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id, identifier, assetType string
		isWildcard                int
	}{
		{"a-wild-bare", "*.acme.test", "domain", 0},
		{"a-wild-url", "https://*.sub.acme.test/", "url", 0},
		{"a-exact", "exact.acme.test", "domain", 0},
		{"a-path-wild", "https://acme.test/*", "url", 0},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type,is_wildcard) VALUES(?,?,?,?,?,?)`,
			r.id, "program-1", "ext-"+r.id, r.identifier, r.assetType, r.isWildcard,
		); err != nil {
			t.Fatal(err)
		}
	}
	entries, linked, err := LoadWatchEligibleScope(ctx, db, "target-1")
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("expected linked=true")
	}
	byID := map[string]WatchScopeEntry{}
	for _, e := range entries {
		byID[e.AssetID] = e
	}
	if len(byID) != 3 {
		t.Fatalf("expected 3 eligible entries (excluding path wildcard), got %+v", entries)
	}
	if e, ok := byID["a-wild-bare"]; !ok || !e.IsWildcard || e.NormalizedHost() != "acme.test" {
		t.Fatalf("*.acme.test with is_wildcard=0 not recognized as wildcard: %+v", e)
	}
	if e, ok := byID["a-wild-url"]; !ok || !e.IsWildcard || e.NormalizedHost() != "sub.acme.test" {
		t.Fatalf("https://*.sub.acme.test/ with is_wildcard=0 not recognized as wildcard: %+v", e)
	}
	if e, ok := byID["a-exact"]; !ok || e.IsWildcard || e.NormalizedHost() != "exact.acme.test" {
		t.Fatalf("exact.acme.test unexpected entry: %+v", e)
	}
	if _, ok := byID["a-path-wild"]; ok {
		t.Fatal("path wildcard https://acme.test/* must not be loaded into watch scope")
	}
}

func TestLandWatchScopeHostsRound1BaselineAndRound2Incremental(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope-baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO targets(id,domain,watch_only) VALUES('t-base','example.test',1)`,
		`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('p-base','hackerone','p-base','acme','Acme')`,
		`INSERT INTO project_programs(target_id,program_id) VALUES('t-base','p-base')`,
		`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type,is_wildcard) VALUES('a-wild','p-base','ext-wild','*.example.test','domain',1)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	// Round 1: no finished watch_scan task, no watch_scope_baselined -> silent baseline.
	r1 := LandWatchScopeHosts(WithTaskID(ctx, "round-1"), db, "t-base", []string{"alpha.example.test"}, nil)
	if len(r1) != 1 || r1[0] != "alpha.example.test" {
		t.Fatalf("round 1 landed = %v, want [alpha.example.test]", r1)
	}
	var assetSource, approval string
	if err := db.QueryRow(`SELECT source, approval_status FROM assets WHERE target_id='t-base' AND value='alpha.example.test'`).Scan(&assetSource, &approval); err != nil {
		t.Fatalf("query round 1 asset: %v", err)
	}
	if assetSource != "watch:scope" || approval != "approved" {
		t.Fatalf("round 1 asset source/approval = %q/%q, want watch:scope/approved", assetSource, approval)
	}
	var announced int
	var metaRaw string
	if err := db.QueryRow(`SELECT announced, COALESCE(metadata,'') FROM watch_scope_events WHERE target_id='t-base' AND identifier='alpha.example.test'`).Scan(&announced, &metaRaw); err != nil {
		t.Fatalf("query round 1 event: %v", err)
	}
	if announced != 1 {
		t.Fatalf("round 1 announced = %d, want 1", announced)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(metaRaw), &meta); err != nil {
		t.Fatalf("unmarshal round 1 metadata %q: %v", metaRaw, err)
	}
	if baseline, _ := meta["baseline"].(bool); !baseline {
		t.Fatalf("round 1 metadata.baseline = %v, want true (meta=%s)", meta["baseline"], metaRaw)
	}

	// Round 2 (after finished watch_scan task or watch_scope_baselined=1): lands new host with announced=0.
	if _, err := db.Exec(`INSERT INTO tasks(id,target_id,type,status,priority,modules,total) VALUES('round-1','t-base','watch_scan','finished',1,'[]',2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE targets SET watch_scope_baselined=1 WHERE id='t-base'`); err != nil {
		t.Fatal(err)
	}
	r2 := LandWatchScopeHosts(WithTaskID(ctx, "round-2"), db, "t-base", []string{"alpha.example.test", "beta.example.test"}, nil)
	if len(r2) != 1 || r2[0] != "beta.example.test" {
		t.Fatalf("round 2 landed = %v, want [beta.example.test]", r2)
	}
	var r2Announced int
	var r2MetaRaw string
	if err := db.QueryRow(`SELECT announced, COALESCE(metadata,'') FROM watch_scope_events WHERE target_id='t-base' AND identifier='beta.example.test'`).Scan(&r2Announced, &r2MetaRaw); err != nil {
		t.Fatalf("query round 2 event: %v", err)
	}
	if r2Announced != 0 {
		t.Fatalf("round 2 announced = %d, want 0", r2Announced)
	}
	var r2Meta map[string]any
	if err := json.Unmarshal([]byte(r2MetaRaw), &r2Meta); err != nil {
		t.Fatalf("unmarshal round 2 metadata %q: %v", r2MetaRaw, err)
	}
	if _, hasBaseline := r2Meta["baseline"]; hasBaseline {
		t.Fatalf("round 2 metadata unexpectedly has baseline=%v", r2Meta["baseline"])
	}
}

func TestLookupWatchAssetCanonicalMatching(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope-lookup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO targets(id,domain,watch_only) VALUES('t-canon','example.com',1)`,
		`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('p-canon','hackerone','p-canon','canon','Canon')`,
		`INSERT INTO project_programs(target_id,program_id) VALUES('t-canon','p-canon')`,
		`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type,is_wildcard) VALUES
			('a-wild','p-canon','ext-wild','*.example.com','domain',1),
			('a-exact','p-canon','ext-exact','example.com','domain',0)`,
		`INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status) VALUES
			('own-1','t-canon','App','https://App.Example.com/','web','url','bounty:hackerone','','approved'),
			('own-2','t-canon','Apex','https://example.com:443/','web','url','manual','','approved'),
			('own-3','t-canon','Path','https://path.example.com/api','web','url','manual','','approved')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	landed := LandWatchScopeHostsWithBaseline(ctx, db, "t-canon", []string{
		"app.example.com",
		"example.com",
		"path.example.com",
	}, false, nil)
	if len(landed) != 1 || landed[0] != "path.example.com" {
		t.Fatalf("landed = %v, want only [path.example.com] (canonical matches must not duplicate)", landed)
	}
	var watchScopeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE target_id='t-canon' AND source='watch:scope'`).Scan(&watchScopeCount); err != nil {
		t.Fatal(err)
	}
	if watchScopeCount != 1 {
		t.Fatalf("watch:scope asset count = %d, want 1", watchScopeCount)
	}
}

func TestIsWatchBaselineRoundMalformedJSON(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope-json.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO targets(id,domain,watch_scope_baselined) VALUES('t-json','json.test',0)`,
		`INSERT INTO watch_scope_events(id,target_id,identifier,event_type,announced,metadata) VALUES
			('we-bad','t-json','a.json.test','landed',1,'{bad-json'),
			('we-empty','t-json','b.json.test','out_of_scope',1,'')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	baseline, err := isWatchBaselineRound(ctx, db, "t-json", "round-2")
	if err != nil {
		t.Fatalf("isWatchBaselineRound returned error on malformed JSON: %v", err)
	}
	if baseline {
		t.Fatalf("isWatchBaselineRound = true, want false when prior landed event exists")
	}
}
