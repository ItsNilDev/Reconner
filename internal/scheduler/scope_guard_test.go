package scheduler

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/recon-platform/internal/scanner"
)

func TestStoreAssetsAreNotScannableRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('sg1','fallback.example.org')`); err != nil {
		t.Fatal(err)
	}
	assets := []struct{ id, value string }{
		{"g1", "https://play.google.com/store/apps/details?id=com.example"},
		{"g2", "https://apps.apple.com/us/app/example/id123456789"},
		{"g4", "https://chromewebstore.google.com/detail/loom/abc"},
		{"g5", "https://marketplace.atlassian.com/apps/1212096/x"},
		{"g6", "Third Party Marketplace Apps"},
		{"g3", "example.com"},
	}
	for _, a := range assets {
		if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind,approval_status) VALUES (?,'sg1','',?,'web','approved')`, a.id, a.value); err != nil {
			t.Fatal(err)
		}
	}

	seeds := s.loadProjectWebSeeds(context.Background(), "sg1")
	if want := []string{"example.com"}; !reflect.DeepEqual(seeds, want) {
		t.Fatalf("web seeds=%v, want %v", seeds, want)
	}

	roots := s.loadSubdomainRoots(context.Background(), "sg1", "fallback.example.org", "")
	if want := []string{"example.com"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("subdomain roots=%v, want %v", roots, want)
	}
}

func TestWildcardAssetSeedsApexNotPattern(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('sgw','fallback.example.org')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind,approval_status,asset_type)
		VALUES ('gw1','sgw','','*.example.com','wildcard','approved','wildcard')`); err != nil {
		t.Fatal(err)
	}

	// The seed loop stores the apex for a wildcard asset. It must never write
	// the literal "*.example.com" as a concrete host.
	seeds := s.loadProjectWebSeeds(context.Background(), "sgw")
	if len(seeds) != 1 || seeds[0] != "*.example.com" {
		t.Fatalf("web seeds=%v, want the raw wildcard asset", seeds)
	}
	roots := normalizeSubdomainRoots(seeds)
	if want := []string{"example.com"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("wildcard seed roots=%v, want %v", roots, want)
	}
}

func TestNormalizeSubdomainRootsDropsStoreValues(t *testing.T) {
	got := normalizeSubdomainRoots([]string{
		"https://play.google.com/store/apps/details?id=com.example",
		"https://marketplace.atlassian.com/apps/1212096/x",
		"apps.apple.com",
		"Third Party Marketplace Apps",
		"apple.com",
		"example.com:8080",
		"example.com",
	})
	want := []string{"apple.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeSubdomainRoots=%v, want %v", got, want)
	}
}

func TestWebScopeHostsDropsAppListings(t *testing.T) {
	cases := []struct {
		scope string
		want  []string
	}{
		{"play.google.com", nil},
		{"https://apps.apple.com/us/app/example/id123456789", nil},
		{"https://chromewebstore.google.com/detail/loom/abc", nil},
		{"https://marketplace.atlassian.com/apps/1212096/x", nil},
		{"Any internal or development services.", nil},
		{"example.com,play.google.com", []string{"example.com"}},
		{"apple.com,example.com", []string{"apple.com", "example.com"}},
	}
	for _, tc := range cases {
		got := webScopeHosts(tc.scope)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("webScopeHosts(%q)=%v, want %v", tc.scope, got, tc.want)
		}
	}
}

func TestStoreOnlyFallbackScopeReturnsNoRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('sg2','play.google.com')`); err != nil {
		t.Fatal(err)
	}
	roots := s.loadSubdomainRoots(context.Background(), "sg2", "play.google.com", "")
	if len(roots) != 0 {
		t.Fatalf("store-only fallback roots=%v, want empty", roots)
	}
}

func TestTaskScopeStateHonorsExactWildcardAndDeny(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain) VALUES ('sc-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES ('sc-p','test','sc-p','sc-p','Program')`)
	_, _ = s.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync) VALUES ('sc-t','sc-p',1)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_program_assets
		(id,program_id,external_id,identifier,asset_type,is_wildcard,in_scope,eligible_submission,active) VALUES
		('sc-a1','sc-p','sc-e1','app.example.test','domain',0,1,1,1),
		('sc-a2','sc-p','sc-e2','*.example.test','wildcard',1,1,1,1)`)

	state, err := s.loadTaskScopeState(ctx, "sc-t")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"app.example.test", true},
		{"other.example.net", false}, // no program rule covers this host
		{"x.example.test", true},     // descendant of a wildcard rule is covered
		{"example.test", false},      // wildcard never covers its apex
	}
	for _, tc := range cases {
		if got := state.allowsHost(ctx, tc.host); got != tc.want {
			t.Errorf("allowsHost(%q)=%v, want %v", tc.host, got, tc.want)
		}
	}

	// An applicable deny wins over a positive program rule.
	if _, err := s.db.Exec(`INSERT INTO target_exclusions(id, target_id, source, program_id, pattern) VALUES ('excl-sc-1', 'sc-t', 'manual', '', '*.example.test')`); err != nil {
		t.Fatal(err)
	}
	state, err = s.loadTaskScopeState(ctx, "sc-t")
	if err != nil {
		t.Fatal(err)
	}
	if state.allowsHost(ctx, "x.example.test") {
		t.Fatal("wildcard exclusion did not override the positive wildcard grant")
	}
}

func TestValidateScopeOverrideRechecksApprovalAndExclusion(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain) VALUES ('ov-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status)
		VALUES ('ov-a','ov-t','','app.example.test','suspended')`)
	state, err := s.loadTaskScopeState(ctx, "ov-t")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validateScopeOverrideE(ctx, "ov-t", "app.example.test", state); err == nil {
		t.Fatal("suspended asset override was accepted")
	}
	_, _ = s.db.Exec(`UPDATE assets SET approval_status='approved' WHERE id='ov-a'`)
	if err := s.validateScopeOverrideE(ctx, "ov-t", "app.example.test", state); err != nil {
		t.Fatalf("approved asset override rejected: %v", err)
	}
	_, _ = s.db.Exec(`UPDATE assets SET metadata='{"out_of_scope":true}' WHERE id='ov-a'`)
	if err := s.validateScopeOverrideE(ctx, "ov-t", "app.example.test", state); err == nil {
		t.Fatal("out-of-scope asset override was accepted")
	}
	_, _ = s.db.Exec(`UPDATE assets SET metadata='{}' WHERE id='ov-a'`)
	if _, err := s.db.Exec(`INSERT INTO target_exclusions(id, target_id, source, program_id, pattern) VALUES ('excl-ov-1', 'ov-t', 'manual', '', 'app.example.test')`); err != nil {
		t.Fatal(err)
	}
	state, err = s.loadTaskScopeState(ctx, "ov-t")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validateScopeOverrideE(ctx, "ov-t", "app.example.test", state); err == nil {
		t.Fatal("excluded asset override was accepted")
	}
}

func TestLoadTaskScopeStateFailsClosedOnReadError(t *testing.T) {
	s := newTestScheduler(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.loadTaskScopeState(ctx, "missing-target"); err == nil {
		t.Fatal("scope read error became a permissive empty scope")
	}
}

func TestLoadProjectWebSeedsSkipsOutOfScopeAssets(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain) VALUES ('sd-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status,asset_type,metadata) VALUES
		('sd-a1','sd-t','','good.example.test','approved','domain','{}'),
		('sd-a2','sd-t','','old.example.test','approved','domain','{"out_of_scope":true}')`)
	state, err := s.loadTaskScopeState(ctx, "sd-t")
	if err != nil {
		t.Fatal(err)
	}
	seeds, err := s.loadProjectWebSeedsE(ctx, "sd-t", state)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 1 || seeds[0] != "good.example.test" {
		t.Fatalf("seeds=%v, want only the in-scope asset", seeds)
	}
	if !strings.Contains(scanner.URLHost("https://good.example.test/x"), "good.example.test") {
		t.Fatal("URLHost did not normalize the seeded host")
	}
}

func TestExecuteTaskBlocksStaleScopeOverrideBeforeIO(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain) VALUES ('stale-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total,scope_override)
		VALUES ('stale-task','stale-t','full_scan','running','["http_probe"]',1,'gone.example.test')`)
	s.executeTask(ctx, "stale-task")

	var status, taskErr string
	if err := s.db.QueryRow(`SELECT status, COALESCE(error,'') FROM tasks WHERE id='stale-task'`).Scan(&status, &taskErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(taskErr, "no longer exists") {
		t.Fatalf("status=%q error=%q, want preflight failure", status, taskErr)
	}
	var subdomains, services int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id='stale-t'`).Scan(&subdomains)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='stale-t'`).Scan(&services)
	if subdomains != 0 || services != 0 {
		t.Fatalf("preflight failure wrote inventory: subdomains=%d services=%d", subdomains, services)
	}
}
