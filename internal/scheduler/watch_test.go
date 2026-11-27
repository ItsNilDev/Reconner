package scheduler

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/recon-platform/internal/scanner"
)

func TestWatchScanModules(t *testing.T) {
	got := watchScanModules()
	want := []string{ModuleSubdomainEnum, ModuleHTTPProbe, "no_subdomain_brute"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchScanModules()=%v, want %v", got, want)
	}
}

func TestResumeTypeTag(t *testing.T) {
	cases := []struct{ in, want string }{
		{watchScanType, watchScanType},
		{monitorWatchType, monitorWatchType},
		{monitorEscalationType, monitorEscalationType},
		{"full_scan", ""},
		{"subdomain_enum", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := resumeTypeTag(tc.in); got != tc.want {
			t.Errorf("resumeTypeTag(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWatchTerminalRulesFinished(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	s.cfg.WatchRoundIntervalHours = 12
	s.cfg.WatchFailLimit = 3
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count) VALUES ('w1','w1.example',1,2)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w1", "finished")

	var failCount int
	var lastRun, nextRun string
	if err := s.db.QueryRow(`SELECT watch_fail_count, COALESCE(watch_last_run,''), COALESCE(watch_next_run,'') FROM targets WHERE id='w1'`).Scan(&failCount, &lastRun, &nextRun); err != nil {
		t.Fatal(err)
	}
	if failCount != 0 {
		t.Fatalf("finished did not reset fail count: %d", failCount)
	}
	if lastRun == "" || nextRun == "" {
		t.Fatalf("finished did not stamp timestamps: last=%q next=%q", lastRun, nextRun)
	}
	next, err := time.Parse("2006-01-02 15:04:05", nextRun)
	if err != nil {
		t.Fatalf("bad next_run layout: %v", err)
	}
	if until := time.Until(next); until <= 11*time.Hour+50*time.Minute || until > 12*time.Hour+10*time.Minute {
		t.Fatalf("next_run gap=%v, want ~12 h", until)
	}
}

func TestWatchTerminalRulesFailureRetriesQuickly(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	s.cfg.WatchRoundIntervalHours = 12
	s.cfg.WatchFailLimit = 3
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count) VALUES ('w6','w6.example',1,0)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w6", "failed")

	var nextRun string
	if err := s.db.QueryRow(`SELECT COALESCE(watch_next_run,'') FROM targets WHERE id='w6'`).Scan(&nextRun); err != nil {
		t.Fatal(err)
	}
	next, err := time.Parse("2006-01-02 15:04:05", nextRun)
	if err != nil {
		t.Fatalf("bad next_run layout: %v", err)
	}
	if until := time.Until(next); until <= 25*time.Minute || until > 31*time.Minute {
		t.Fatalf("failed next_run gap=%v, want ~30 min retry", until)
	}
}

func TestWatchRoundIntervalFallback(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundIntervalHours = 0
	if got := s.watchRoundIntervalMinutes(); got != 720 {
		t.Fatalf("watchRoundIntervalMinutes()=%d, want 720", got)
	}
}

func TestWatchTerminalRulesFailureChainStopsAtLimit(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchFailLimit = 2
	s.cfg.WatchRoundsMinGap = 30
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count,watch_paused) VALUES ('w2','w2.example',1,1,0)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w2", "failed")

	var fails, paused int
	var nextRun *string
	if err := s.db.QueryRow(`SELECT watch_fail_count, COALESCE(watch_paused,0), watch_next_run FROM targets WHERE id='w2'`).Scan(&fails, &paused, &nextRun); err != nil {
		t.Fatal(err)
	}
	if fails != 2 || paused != 1 || nextRun != nil {
		t.Fatalf("failure limit: fails=%d paused=%d next=%v, want 2/1/NULL", fails, paused, nextRun)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id='w2' AND type='watch_failed'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("watch_failed notification count=%d err=%v, want 1", n, err)
	}
}

func TestWatchTerminalRulesCancelledStopsChain(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_paused,watch_next_run) VALUES ('w3','w3.example',1,0,'2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	s.applyWatchTerminalRules("w3", "cancelled")
	var paused int
	var nextRun *string
	if err := s.db.QueryRow(`SELECT COALESCE(watch_paused,0), watch_next_run FROM targets WHERE id='w3'`).Scan(&paused, &nextRun); err != nil {
		t.Fatal(err)
	}
	if paused != 1 || nextRun != nil {
		t.Fatalf("cancelled: paused=%d next=%v, want 1/NULL", paused, nextRun)
	}
}

func TestWatchRoundKeepsAllRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_root_index) VALUES ('w4','w4.example',1,1)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind,asset_type,approval_status) VALUES (?,'w4','',?,'web','domain','approved')`, id, id+".example"); err != nil {
			t.Fatal(err)
		}
	}
	roots := s.loadSubdomainRoots(context.Background(), "w4", "w4.example", "")
	if len(roots) != 3 {
		t.Fatalf("roots=%v, want all 3", roots)
	}
}

func TestWatchOnlyTargetsExcludeDeepProjects(t *testing.T) {
	s := newTestScheduler(t)
	// w5: only watch tasks -> eligible for prune. An unscheduled target is not
	// eligible, so give it a due time.
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_next_run) VALUES ('w5','w5.example',1,'2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status) VALUES ('t1','w5','watch_scan','finished')`); err != nil {
		t.Fatal(err)
	}
	// w6: has a deep task -> NOT eligible (keeps every row).
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only) VALUES ('w6','w6.example',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status) VALUES ('t2','w6','full_scan','finished')`); err != nil {
		t.Fatal(err)
	}
	got := s.watchOnlyTargets()
	want := []string{"w5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchOnlyTargets=%v, want %v", got, want)
	}
}

func TestWatchKindGuardNotifiesOnce(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,kind) VALUES ('w7','w7.example',1,'mixed')`); err != nil {
		t.Fatal(err)
	}
	s.checkWatchKindGuard()
	s.checkWatchKindGuard() // second call must not duplicate
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id='w7' AND type='watch_kind_conflict'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("watch_kind_conflict count=%d err=%v, want 1", n, err)
	}
}

func TestRecoverWatchTaskAdvancesSchedule(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_next_run,watch_paused) VALUES ('w8','w8.example',1,'2020-01-01 00:00:00',0)`); err != nil {
		t.Fatal(err)
	}
	s.recoverWatchTask("w8")
	var fails int
	var next string
	if err := s.db.QueryRow(`SELECT watch_fail_count, watch_next_run FROM targets WHERE id='w8'`).Scan(&fails, &next); err != nil {
		t.Fatal(err)
	}
	if fails != 1 || next == "2020-01-01 00:00:00" {
		t.Fatalf("recover: fails=%d next=%q", fails, next)
	}
}

func TestWatchLinkedExactDomainSkipsSubdomainEnumUpsertsSeedAndCompletesProgress(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_next_run,watch_paused)
		VALUES ('w-exact','hey.com',1,'2020-01-01 00:00:00',0)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES ('w-exact-p','hackerone','w-exact-p','w-exact-p','ExactProg')`)
	_, _ = s.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync) VALUES ('w-exact','w-exact-p',1)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_program_assets
		(id,program_id,external_id,identifier,asset_type,is_wildcard,in_scope,eligible_submission,active) VALUES
		('w-exact-pa1','w-exact-p','e1','hey.com','domain',0,1,1,1),
		('w-exact-pa2','w-exact-p','e2','alive.hey.com','domain',0,1,1,1),
		('w-exact-pa3','w-exact-p','e3','vhost.hey.com','domain',0,1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,kind,asset_type,approval_status) VALUES
		('w-exact-a1','w-exact','','hey.com','web','domain','approved'),
		('w-exact-a2','w-exact','','alive.hey.com','web','domain','approved'),
		('w-exact-a3','w-exact','','vhost.hey.com','web','domain','approved')`)

	// Pre-existing subdomain rows that would have been dropped by ON CONFLICT DO NOTHING:
	// 1) hey.com: source='dns', ip='', catchall=1 -> must upgrade to source='seed', catchall=0.
	// 2) alive.hey.com: source='dns', ip='1.2.3.4', is_alive=1 -> must keep ip/is_alive and upgrade source='seed'.
	// 3) vhost.hey.com: source='vhost', ip='5.6.7.8', is_alive=1, catchall=1 -> must preserve 'vhost'/ip/is_alive and reset catchall=0.
	_, _ = s.db.Exec(`INSERT INTO subdomains(id,target_id,subdomain,ip,is_alive,source,catchall) VALUES
		('sub-1','w-exact','hey.com','',0,'dns',1),
		('sub-2','w-exact','alive.hey.com','1.2.3.4',1,'dns',0),
		('sub-3','w-exact','vhost.hey.com','5.6.7.8',1,'vhost',1)`)

	state, err := s.loadTaskScopeState(ctx, "w-exact")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := s.loadSubdomainRootsForTaskE(ctx, "w-exact", "hey.com", "", state, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 0 {
		t.Fatalf("exact-domain watch roots=%v, want empty", roots)
	}
	seeds, err := s.loadProjectWebSeedsE(ctx, "w-exact", state)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"hey.com", "alive.hey.com", "vhost.hey.com"}; !reflect.DeepEqual(seeds, want) {
		t.Fatalf("exact-domain seeds=%v, want %v", seeds, want)
	}

	// Run executeTask with [subdomain_enum, verify] (verify needs no network).
	task, err := s.CreateTaskTyped("w-exact", []string{ModuleSubdomainEnum, ModuleVerify}, 3, watchScanType)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(ctx, task.ID)

	var taskStatus, taskErr string
	var progress, total int
	if err := s.db.QueryRow(`SELECT status, COALESCE(error,''), progress, total FROM tasks WHERE id=?`, task.ID).
		Scan(&taskStatus, &taskErr, &progress, &total); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" || progress != 2 || total != 2 {
		t.Fatalf("task status=%q err=%q progress=%d/%d, want finished 2/2", taskStatus, taskErr, progress, total)
	}

	var phaseStatus, phaseReason string
	if err := s.db.QueryRow(`SELECT status, reason FROM task_phases WHERE task_id=? AND module=?`,
		task.ID, ModuleSubdomainEnum).Scan(&phaseStatus, &phaseReason); err != nil {
		t.Fatal(err)
	}
	const wantReason = "exact-domain program scope (no approved wildcard assets)"
	if phaseStatus != "skipped" || phaseReason != wantReason {
		t.Fatalf("subdomain_enum phase status=%q reason=%q, want skipped / %q", phaseStatus, phaseReason, wantReason)
	}

	// Verify upgraded seed rows.
	type subRow struct {
		source   string
		ip       string
		isAlive  int
		catchall int
	}
	checkSub := func(host string, want subRow) {
		t.Helper()
		var got subRow
		if err := s.db.QueryRow(`SELECT source, ip, is_alive, catchall FROM subdomains WHERE target_id='w-exact' AND subdomain=?`, host).
			Scan(&got.source, &got.ip, &got.isAlive, &got.catchall); err != nil {
			t.Fatalf("query subdomain %s: %v", host, err)
		}
		if got != want {
			t.Fatalf("subdomain %s = %+v, want %+v", host, got, want)
		}
	}
	checkSub("hey.com", subRow{source: "seed", ip: "", isAlive: 0, catchall: 0})
	checkSub("alive.hey.com", subRow{source: "seed", ip: "1.2.3.4", isAlive: 1, catchall: 0})
	checkSub("vhost.hey.com", subRow{source: "vhost", ip: "5.6.7.8", isAlive: 1, catchall: 0})
}

func TestWatchLinkedPendingWildcardBlockedUntilApproved(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain,watch_only) VALUES ('w-pend','hey.com',1)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES ('w-pend-p','hackerone','w-pend-p','w-pend-p','PendProg')`)
	_, _ = s.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync) VALUES ('w-pend','w-pend-p',1)`)
	// Exact hey.com + pending upstream *.hey.com (NOT yet in assets).
	_, _ = s.db.Exec(`INSERT INTO bounty_program_assets
		(id,program_id,external_id,identifier,asset_type,is_wildcard,in_scope,eligible_submission,active) VALUES
		('w-pend-pa1','w-pend-p','e1','hey.com','domain',0,1,1,1),
		('w-pend-pa2','w-pend-p','e2','*.hey.com','wildcard',1,1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,kind,asset_type,approval_status)
		VALUES ('w-pend-a1','w-pend','','hey.com','web','domain','approved')`)

	state, err := s.loadTaskScopeState(ctx, "w-pend")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := s.loadSubdomainRootsForTaskE(ctx, "w-pend", "hey.com", "", state, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 0 {
		t.Fatalf("pending wildcard roots=%v, want empty", roots)
	}
	approvedEntries := approvedWatchScopeEntries(state.entries, roots)
	if _, _, ok := scanner.HostMatchesWatchScope(approvedEntries, "sub.hey.com"); ok {
		t.Fatal("pending wildcard allowed sub.hey.com before approval")
	}
	if _, _, ok := scanner.HostMatchesWatchScope(approvedEntries, "hey.com"); !ok {
		t.Fatal("approved exact host hey.com was dropped from strict watch scope")
	}

	// Narrower approved wildcard *.sub.hey.com under program *.hey.com must not widen to all of *.hey.com.
	narrowedEntries := approvedWatchScopeEntries(state.entries, []string{"sub.hey.com"})
	if _, _, ok := scanner.HostMatchesWatchScope(narrowedEntries, "a.sub.hey.com"); !ok {
		t.Fatal("narrowed approved wildcard rejected a.sub.hey.com")
	}
	if _, _, ok := scanner.HostMatchesWatchScope(narrowedEntries, "other.hey.com"); ok {
		t.Fatal("narrowed approved wildcard widened to other.hey.com")
	}

	// Approve *.hey.com in project assets -> roots becomes ["hey.com"] and strict watch scope allows sub.hey.com.
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,kind,asset_type,approval_status)
		VALUES ('w-pend-a2','w-pend','','*.hey.com','web','wildcard','approved')`)
	state, err = s.loadTaskScopeState(ctx, "w-pend")
	if err != nil {
		t.Fatal(err)
	}
	roots, err = s.loadSubdomainRootsForTaskE(ctx, "w-pend", "hey.com", "", state, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"hey.com"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("approved wildcard roots=%v, want %v", roots, want)
	}
	approvedEntries = approvedWatchScopeEntries(state.entries, roots)
	if _, _, ok := scanner.HostMatchesWatchScope(approvedEntries, "sub.hey.com"); !ok {
		t.Fatal("approved wildcard did not allow sub.hey.com in strict watch scope")
	}
}

func TestWatchLinkedMixedScopeOnlyEnumeratesWildcardRoots(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain,watch_only) VALUES ('w-mix','foo.com',1)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES ('w-mix-p','hackerone','w-mix-p','w-mix-p','MixProg')`)
	_, _ = s.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync) VALUES ('w-mix','w-mix-p',1)`)
	_, _ = s.db.Exec(`INSERT INTO bounty_program_assets
		(id,program_id,external_id,identifier,asset_type,is_wildcard,in_scope,eligible_submission,active) VALUES
		('w-mix-pa1','w-mix-p','e1','*.foo.com','wildcard',1,1,1,1),
		('w-mix-pa2','w-mix-p','e2','bar.com','domain',0,1,1,1),
		('w-mix-pa3','w-mix-p','e3','https://baz.com/','url',0,1,1,1),
		('w-mix-pa4','w-mix-p','e4','https://qux.com/*','url',1,1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO assets(id,target_id,name,value,kind,asset_type,approval_status) VALUES
		('w-mix-a1','w-mix','','*.foo.com','web','wildcard','approved'),
		('w-mix-a2','w-mix','','bar.com','web','domain','approved'),
		('w-mix-a3','w-mix','','https://baz.com/','web','url','approved'),
		('w-mix-a4','w-mix','','https://qux.com/*','web','url','approved')`)

	state, err := s.loadTaskScopeState(ctx, "w-mix")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := s.loadSubdomainRootsForTaskE(ctx, "w-mix", "foo.com", "", state, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"foo.com"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("mixed watch roots=%v, want %v", roots, want)
	}
	seeds, err := s.loadProjectWebSeedsE(ctx, "w-mix", state)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"*.foo.com", "bar.com", "https://baz.com/"}; !reflect.DeepEqual(seeds, want) {
		t.Fatalf("mixed watch seeds=%v, want %v", seeds, want)
	}
}
