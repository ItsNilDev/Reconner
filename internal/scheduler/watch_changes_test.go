package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/recon-platform/internal/scanner"
)

func TestWatchHTTPServicesFromDatabase(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code, title, server, technologies)
		VALUES ('h1','t1','https://a.example',403,'Forbidden','nginx','["react","jquery"]')`); err != nil {
		t.Fatalf("insert http service: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, is_alive)
		VALUES ('s1','t1','a.example',1)`); err != nil {
		t.Fatalf("insert subdomain: %v", err)
	}

	httpSnap, err := batchWatchHTTPServices(ctx, s.db, "t1")
	if err != nil {
		t.Fatalf("batchWatchHTTPServices: %v", err)
	}
	got, ok := httpSnap["a.example"]
	if !ok || got.URL != "https://a.example" || got.StatusCode != 403 || got.Title != "Forbidden" || got.Server != "nginx" || got.Technologies != "jquery, react" {
		t.Fatalf("batch http snapshot = %+v", got)
	}

	svc := watchHTTPServiceForHost(ctx, s.db, "t1", "a.example")
	if svc.URL != "https://a.example" || svc.StatusCode != 403 || svc.Title != "Forbidden" || svc.Technologies != "jquery, react" {
		t.Fatalf("watchHTTPServiceForHost = %+v", svc)
	}
	if unknown := watchHTTPServiceForHost(ctx, s.db, "t1", "unknown.example"); unknown.URL != "" {
		t.Fatalf("unknown host service = %+v, want empty", unknown)
	}

	fp := watchFingerprint(svc)
	if fp == "" {
		t.Fatal("watchFingerprint is empty")
	}
	// URL and technologies are not part of the grouping fingerprint.
	clone := svc
	clone.URL = "https://other.example"
	clone.Technologies = "vue"
	if watchFingerprint(clone) != fp {
		t.Fatal("fingerprint changed with URL/technologies")
	}
	clone.Server = "apache"
	if watchFingerprint(clone) == fp {
		t.Fatal("fingerprint did not change with server")
	}
}

func TestPruneWatchChangeRowsUsesGlobalWindow(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchChangesRetentionDays = 1
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	insert := func(id, detected string) {
		if _, err := s.db.Exec(`INSERT INTO watch_round_changes
			(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)`, id, "t1", "round-1", "https://a.example",
			"status_change", "old", "new", "medium", "{}", detected); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	insert("old", time.Now().AddDate(0, 0, -10).UTC().Format("2006-01-02 15:04:05"))
	insert("new", time.Now().UTC().Format("2006-01-02 15:04:05"))

	s.pruneWatchChangeRows()

	var ids []string
	rows, err := s.db.Query(`SELECT id FROM watch_round_changes ORDER BY id`)
	if err != nil {
		t.Fatalf("query rows: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 1 || ids[0] != "new" {
		t.Fatalf("remaining ids = %v, want [new]", ids)
	}
}

func TestEmitWatchNewHostsBaselineMarksWithoutFeedRows(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	stmts := []string{
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','a.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','b.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at) VALUES ('t1','never-alive.example','2026-01-01 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-a','t1','a.example',1)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-b','t1','b.example',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	// No other finished watch_scan task: this round is the baseline.
	got := s.emitWatchNewHosts(ctx, "round-1", "t1")
	if len(got) != 0 {
		t.Fatalf("baseline emitted %+v, want no events", got)
	}

	var pending int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='t1'
		AND first_alive_at IS NOT NULL AND announced_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending alive hosts = %d, err = %v, want 0", pending, err)
	}
	var marked int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='t1'
		AND host='never-alive.example' AND announced_at IS NOT NULL`).Scan(&marked); err != nil || marked != 0 {
		t.Fatalf("baseline marked never-alive host: count = %d, err = %v", marked, err)
	}
	var rows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("baseline feed rows = %d, err = %v, want 0", rows, err)
	}
}

func TestEmitWatchNewHostsEmitsOnceAndMarksAnnounced(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`,
		// A previous finished round makes the current round a non-baseline.
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','t1','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','a.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','never-alive.example','2026-01-01 00:00:00',NULL)`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','offline.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at,announced_at) VALUES ('t1','announced.example','2026-01-01 00:00:00','2026-01-02 00:00:00','2026-01-03 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-a','t1','a.example',1)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-never','t1','never-alive.example',1)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-offline','t1','offline.example',0)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-announced','t1','announced.example',1)`,
		`INSERT INTO http_services (id,target_id,url,status_code,title,server,technologies)
			VALUES ('h1','t1','https://a.example',200,'OK','nginx','["react"]')`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-1", "t1")
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1: %+v", len(got), got)
	}
	c := got[0]
	if c.ChangeType != "new_subdomain" || c.NewValue != "a.example" || c.Severity != "medium" {
		t.Fatalf("event = %+v, want medium new_subdomain for a.example", c)
	}
	if c.URL != "https://a.example" {
		t.Errorf("event url = %q, want https://a.example", c.URL)
	}
	var meta struct {
		Host   string   `json:"host"`
		Hosts  []string `json:"hosts"`
		Source string   `json:"source"`
		Status int      `json:"status"`
		Total  int      `json:"total"`
	}
	if err := json.Unmarshal([]byte(c.Metadata), &meta); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if meta.Host != "a.example" || len(meta.Hosts) != 1 || meta.Hosts[0] != "a.example" {
		t.Errorf("metadata hosts = %+v, want [a.example]", meta)
	}
	if meta.Source != "watch" || meta.Status != 200 || meta.Total != 1 {
		t.Errorf("metadata = %+v, want source=watch status=200 total=1", meta)
	}

	// The event row and the announced marker are written together.
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id='t1'
		AND task_id='round-1' AND change_type='new_subdomain'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("feed rows = %d, err = %v, want 1", count, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='t1'
		AND host='a.example' AND announced_at IS NOT NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("announced live host count = %d, err = %v, want 1", count, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='t1'
		AND host='offline.example' AND announced_at IS NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("offline host unannounced count = %d, err = %v, want 1", count, err)
	}

	// A second round must not announce the same host twice.
	again := s.emitWatchNewHosts(ctx, "round-2", "t1")
	if len(again) != 0 {
		t.Fatalf("second round emitted %+v, want no events", again)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id='t1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("feed rows after second round = %d, err = %v, want 1", count, err)
	}
}

func TestEmitWatchNewHostsSkipsWildcardScopePatterns(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`,
		`INSERT INTO bounty_programs (id, provider, external_id, handle, name) VALUES ('p1','hackerone','p1','p1','P1')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','t1','watch_scan','finished',1,'[]',1)`,
		// The bad row a wildcard asset used to create in the seed loop.
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','*.example.com','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-wild','t1','*.example.com',1)`,
		// A real host must still be announced.
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','a.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-a','t1','a.example',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-1", "t1")
	if len(got) != 1 || got[0].NewValue != "a.example" {
		t.Fatalf("emitted %+v, want one event for a.example only", got)
	}
	var feedRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id='t1'
		AND (new_value LIKE '%*%' OR metadata LIKE '%*.example.com%')`).Scan(&feedRows); err != nil || feedRows != 0 {
		t.Fatalf("wildcard feed rows = %d, err = %v, want 0", feedRows, err)
	}
	var wildcardPending int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='t1'
		AND host='*.example.com' AND announced_at IS NULL`).Scan(&wildcardPending); err != nil || wildcardPending != 0 {
		t.Fatalf("wildcard row left pending = %d, err = %v, want 0", wildcardPending, err)
	}
}

func TestEmitWatchNewHostsGroupsIdenticalFingerprints(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','t1','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','a.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES ('t1','b.example','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-a','t1','a.example',1)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-b','t1','b.example',1)`,
		`INSERT INTO http_services (id,target_id,url,status_code,title,server)
			VALUES ('h1','t1','https://a.example',200,'OK','nginx')`,
		`INSERT INTO http_services (id,target_id,url,status_code,title,server)
			VALUES ('h2','t1','https://b.example',200,'OK','nginx')`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-1", "t1")
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want one grouped event: %+v", len(got), got)
	}
	var meta struct {
		Hosts []string `json:"hosts"`
		Total int      `json:"total"`
	}
	if err := json.Unmarshal([]byte(got[0].Metadata), &meta); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if len(meta.Hosts) != 2 || meta.Hosts[0] != "a.example" || meta.Hosts[1] != "b.example" || meta.Total != 2 {
		t.Fatalf("grouped hosts = %+v, want [a.example b.example] with total 2", meta)
	}
}

func TestFlushScopeLandingsClosesAuditSilently(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO watch_scope_events
		(id,target_id,identifier,event_type,announced) VALUES ('we-1','t1','a.example','landed',0)`); err != nil {
		t.Fatalf("insert scope event: %v", err)
	}

	s.flushScopeLandings()

	var announced int
	if err := s.db.QueryRow(`SELECT announced FROM watch_scope_events WHERE id='we-1'`).Scan(&announced); err != nil || announced != 1 {
		t.Fatalf("announced = %d, err = %v, want 1", announced, err)
	}
	var bells int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&bells); err != nil || bells != 0 {
		t.Fatalf("notifications = %d, err = %v, want 0 (landing writes no bell)", bells, err)
	}
	var feedRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes`).Scan(&feedRows); err != nil || feedRows != 0 {
		t.Fatalf("watch feed rows = %d, err = %v, want 0", feedRows, err)
	}
}

func TestPruneOrphanChangeSeen(t *testing.T) {
	s := newTestScheduler(t)
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`,
		`INSERT INTO bounty_programs (id, provider, external_id, handle, name) VALUES ('p1','hackerone','p1','p1','P1')`,
		`INSERT INTO tasks (id, target_id, type, status, priority, modules, total)
			VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`,
		`INSERT INTO monitoring_changes (id,target_id,url,change_type,detected_at)
			VALUES ('mc-1','t1','https://a.example','status_change','` + now + `')`,
		`INSERT INTO watch_round_changes
			(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES ('wc-1','t1','round-1','https://a.example','new_subdomain','','a.example','medium','{}','` + now + `')`,
		`INSERT INTO watch_scope_events (id,target_id,identifier,event_type,detected_at)
			VALUES ('we-1','t1','a.example','landed','` + now + `')`,
		`INSERT INTO bounty_scope_events (id,target_id,program_id,event_type,identifier,detected_at)
			VALUES ('be-1','t1','p1','rule_added','a.example','` + now + `')`,
		`INSERT INTO notifications (id,target_id,type,title,created_at)
			VALUES ('n-1','t1','watch_failed','Round failed','` + now + `')`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	for _, id := range []string{"mc-1", "wc-1", "we-1", "be-1", "n-1", "dead-1"} {
		if _, err := s.db.Exec(`INSERT INTO change_seen (change_id,user_id,seen_at) VALUES (?,1,?)`, id, now); err != nil {
			t.Fatalf("insert seen %s: %v", id, err)
		}
	}

	s.pruneOrphanChangeSeen()

	var ids []string
	rows, err := s.db.Query(`SELECT change_id FROM change_seen ORDER BY change_id`)
	if err != nil {
		t.Fatalf("query seen: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan seen: %v", err)
		}
		ids = append(ids, id)
	}
	want := []string{"be-1", "mc-1", "n-1", "wc-1", "we-1"}
	if len(ids) != len(want) {
		t.Fatalf("remaining ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("remaining ids = %v, want %v", ids, want)
		}
	}
}

func TestFinishPhaseCancelsPhaseContext(t *testing.T) {
	s := newTestScheduler(t)
	modCtx, finish := s.beginPhase(context.Background(), "task-phase-cancel", time.Minute)
	if err := modCtx.Err(); err != nil {
		t.Fatalf("phase context already done before finish: %v", err)
	}
	_, _ = finish()
	if err := modCtx.Err(); err == nil {
		t.Fatal("finishPhase must cancel the phase context")
	}
}

func TestShouldWriteWatchDiffGates(t *testing.T) {
	if !shouldWriteWatchDiff(watchScanType, false, false, nil, nil, true) {
		t.Fatal("clean watch phase must write a diff")
	}
	// Reading modCtx.Err() after finishPhase returns context.Canceled. The gate
	// must reject that value so it never silently drops a clean diff.
	if shouldWriteWatchDiff(watchScanType, false, false, nil, context.Canceled, true) {
		t.Fatal("cancelled phase context must not write a diff")
	}
	if shouldWriteWatchDiff("monitor_watch", false, false, nil, nil, true) {
		t.Fatal("monitor_watch must not write a watch diff")
	}
	if shouldWriteWatchDiff(watchScanType, true, false, nil, nil, true) {
		t.Fatal("skipped phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, true, nil, nil, true) {
		t.Fatal("timed-out phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, false, context.Canceled, nil, true) {
		t.Fatal("failed phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, false, nil, nil, false) {
		t.Fatal("missing snapshots must not write a diff")
	}
}

func TestWatchHTTPServiceForHostMatchesExactHost(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('exact-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
		('s-a','exact-t','a.example.test',1), ('s-b','exact-t','a.example.test.evil.test',1)`)
	_, _ = s.db.Exec(`INSERT INTO http_services (id,target_id,subdomain_id,url,status_code,title)
		VALUES ('h-a','exact-t','s-a','https://a.example.test/',200,'Good'),
		       ('h-b','exact-t','s-b','https://a.example.test.evil.test/',403,'Impostor')`)

	got := watchHTTPServiceForHost(ctx, s.db, "exact-t", "a.example.test")
	if got.URL != "https://a.example.test/" || got.StatusCode != 200 || got.Title != "Good" {
		t.Fatalf("service = %+v, want the exact host's service", got)
	}
	other := watchHTTPServiceForHost(ctx, s.db, "exact-t", "a.example.test.evil.test")
	if other.URL != "https://a.example.test.evil.test/" || other.StatusCode != 403 {
		t.Fatalf("service = %+v, want the overlapping host's own service", other)
	}
}

func TestEmitWatchNewHostsManualProjectUsesProjectScope(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('manual-t','example.test')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','manual-t','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO assets (id,target_id,value,asset_type,approval_status) VALUES ('a-in','manual-t','in.example.test','domain','approved')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES
			('manual-t','in.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00'),
			('manual-t','out.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
			('s-in','manual-t','in.example.test',1), ('s-out','manual-t','out.example.test',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-2", "manual-t")
	if len(got) != 1 {
		t.Fatalf("events = %+v, want one grouped event", got)
	}
	var meta struct {
		Members []struct {
			Host    string `json:"host"`
			InScope bool   `json:"in_scope"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(got[0].Metadata), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Members) != 2 {
		t.Fatalf("members = %+v, want both hosts with separate scope flags", meta.Members)
	}
	scopeByHost := map[string]bool{}
	for _, m := range meta.Members {
		scopeByHost[m.Host] = m.InScope
	}
	if !scopeByHost["in.example.test"] || scopeByHost["out.example.test"] {
		t.Fatalf("members = %+v, want only the project asset in scope", meta.Members)
	}
}

func TestWatchHTTPServiceSkipsStatusZeroAndPrefersHTTPS(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	_, _ = s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('svc-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-svc','svc-t','a.example.test',1)`)
	_, _ = s.db.Exec(`INSERT INTO http_services (id,target_id,subdomain_id,url,status_code,title)
		VALUES ('h-zero','svc-t','s-svc','https://a.example.test/old',0,'Seed'),
		       ('h-plain','svc-t',NULL,'http://a.example.test/',200,'HTTP'),
		       ('h-secure','svc-t',NULL,'https://a.example.test/',200,'HTTPS')`)
	got := watchHTTPServiceForHost(ctx, s.db, "svc-t", "a.example.test")
	if got.URL != "https://a.example.test/" || got.Title != "HTTPS" {
		t.Fatalf("service = %+v, want the https 200 row", got)
	}
}

func TestBatchWatchHTTPServicesExactHostAndHTTPSPreference(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('batch-t','example.test')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
			('s-a','batch-t','a.example.test',1),
			('s-b','batch-t','a.example.test.evil.test',1)`,
		`INSERT INTO http_services (id,target_id,subdomain_id,url,status_code,title,technologies) VALUES
			('h-zero','batch-t','s-a','https://a.example.test/old',0,'Seed','[]'),
			('h-plain','batch-t','s-a','http://a.example.test/',200,'HTTP','["nginx"]'),
			('h-secure','batch-t',NULL,'https://a.example.test:8443/',200,'HTTPS','["react","jquery"]'),
			('h-evil','batch-t','s-b','https://a.example.test.evil.test/',403,'Impostor','[]')`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got, err := batchWatchHTTPServices(ctx, s.db, "batch-t")
	if err != nil {
		t.Fatalf("batchWatchHTTPServices: %v", err)
	}
	a := got["a.example.test"]
	if a.URL != "https://a.example.test:8443/" || a.Title != "HTTPS" || a.Technologies != "jquery, react" {
		t.Fatalf("a.example.test service = %+v, want https 200 row", a)
	}
	evil := got["a.example.test.evil.test"]
	if evil.URL != "https://a.example.test.evil.test/" || evil.StatusCode != 403 || evil.Title != "Impostor" {
		t.Fatalf("a.example.test.evil.test service = %+v, want impostor 403 row", evil)
	}
	if _, ok := got["missing.example.test"]; ok {
		t.Fatalf("unexpected entry for missing host")
	}
}

func TestEmitWatchNewHostsSkipsDeadHosts(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('dead-t','example.test')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','dead-t','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES
			('dead-t','dead.example.test','2026-01-01 00:00:00',CURRENT_TIMESTAMP),
			('dead-t','live.example.test','2026-01-01 00:00:00',CURRENT_TIMESTAMP)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
			('s-dead','dead-t','dead.example.test',0),
			('s-live','dead-t','live.example.test',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	got := s.emitWatchNewHosts(ctx, "round-1", "dead-t")
	if len(got) != 1 || got[0].NewValue != "live.example.test" {
		t.Fatalf("events = %+v, want only live.example.test", got)
	}
	var liveAnnounced, deadUnannounced int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='dead-t' AND host='live.example.test' AND announced_at IS NOT NULL`).Scan(&liveAnnounced); err != nil {
		t.Fatal(err)
	}
	if liveAnnounced != 1 {
		t.Fatalf("live host announced = %d, want 1", liveAnnounced)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='dead-t' AND host='dead.example.test' AND announced_at IS NULL`).Scan(&deadUnannounced); err != nil {
		t.Fatal(err)
	}
	if deadUnannounced != 1 {
		t.Fatalf("dead host unannounced = %d, want 1 (must remain NULL)", deadUnannounced)
	}
}

func TestFlushScopeLandingsSkipsOutOfScope(t *testing.T) {
	s := newTestScheduler(t)
	_, _ = s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('scope-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO watch_scope_events (id,target_id,identifier,event_type,announced,detected_at)
		VALUES ('lost','scope-t','a.example.test','out_of_scope',0,datetime('now')),
		       ('landed','scope-t','b.example.test','landed',0,datetime('now'))`)
	s.flushScopeLandings()
	var lost, landed int
	if err := s.db.QueryRow(`SELECT announced FROM watch_scope_events WHERE id='lost'`).Scan(&lost); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT announced FROM watch_scope_events WHERE id='landed'`).Scan(&landed); err != nil {
		t.Fatal(err)
	}
	if lost != 1 {
		t.Fatalf("out_of_scope announced=%d, want 1 (consumed without alert)", lost)
	}
	if landed != 2 && landed != 1 {
		t.Fatalf("landed announced=%d, want claimed/sent", landed)
	}
}

// A window with no landed or re_eligible rows must still consume out_of_scope
// history. No notifier is configured, so the row must close without a message.
func TestFlushScopeLandingsConsumesOutOfScopeWithoutLandings(t *testing.T) {
	s := newTestScheduler(t)
	_, _ = s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('scope-t','example.test')`)
	_, _ = s.db.Exec(`INSERT INTO watch_scope_events (id,target_id,identifier,event_type,announced,detected_at)
		VALUES ('lost','scope-t','a.example.test','out_of_scope',0,datetime('now'))`)

	s.flushScopeLandings()

	var announced int
	if err := s.db.QueryRow(`SELECT announced FROM watch_scope_events WHERE id='lost'`).Scan(&announced); err != nil {
		t.Fatal(err)
	}
	if announced != 1 {
		t.Fatalf("out_of_scope announced=%d, want 1 (consumed in an empty landing window)", announced)
	}
	var bells int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&bells); err != nil {
		t.Fatal(err)
	}
	if bells != 0 {
		t.Fatalf("notifications=%d, want 0 (no notifier message required)", bells)
	}
}

func TestEmitWatchNewHostsBaselineFallbackAfterTaskPrune(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('prune-t','example.test')`,
		// No finished tasks remain (e.g. pruned after 90 days), but prior
		// watch_hosts already have announced_at set from earlier rounds.
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at,announced_at) VALUES
			('prune-t','old.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00','2026-01-03 00:00:00')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES
			('prune-t','new.example.test','2026-04-01 00:00:00','2026-04-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
			('s-old','prune-t','old.example.test',1),
			('s-new','prune-t','new.example.test',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-after-prune", "prune-t")
	if len(got) != 1 || got[0].NewValue != "new.example.test" {
		t.Fatalf("events = %+v, want one event for new.example.test", got)
	}
	var announced int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='prune-t' AND host='new.example.test' AND announced_at IS NOT NULL`).Scan(&announced); err != nil {
		t.Fatal(err)
	}
	if announced != 1 {
		t.Fatalf("announced new.example.test = %d, want 1", announced)
	}
}

func TestEmitWatchNewHostsRanksInScopeAheadOfOutOfScope(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('rank-t','example.test')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
		VALUES ('round-0','rank-t','watch_scan','finished',1,'[]',1)`); err != nil {
		t.Fatalf("insert task: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,value,asset_type,approval_status)
		VALUES ('a-in','rank-t','in.example.test','domain','approved')`); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	// 20 out-of-scope hosts with rich 200-OK HTTP services (high score, unique fingerprints).
	for i := 1; i <= 20; i++ {
		host := fmt.Sprintf("out-%02d.example.test", i)
		if _, err := s.db.Exec(`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at)
			VALUES ('rank-t',?,'2026-01-01 00:00:00','2026-01-02 00:00:00')`, host); err != nil {
			t.Fatalf("insert out watch_host %d: %v", i, err)
		}
		if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive)
			VALUES (?,'rank-t',?,1)`, fmt.Sprintf("s-out-%02d", i), host); err != nil {
			t.Fatalf("insert out subdomain %d: %v", i, err)
		}
		if _, err := s.db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,server,technologies)
			VALUES (?,'rank-t',?,200,?,'nginx','["react"]')`,
			fmt.Sprintf("h-out-%02d", i), "https://"+host, fmt.Sprintf("Out Title %02d", i)); err != nil {
			t.Fatalf("insert out http_service %d: %v", i, err)
		}
	}
	// 1 in-scope host with no HTTP service (lower raw score than the 20 out-of-scope hosts).
	if _, err := s.db.Exec(`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at)
		VALUES ('rank-t','in.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00')`); err != nil {
		t.Fatalf("insert in watch_host: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,is_alive)
		VALUES ('s-in','rank-t','in.example.test',1)`); err != nil {
		t.Fatalf("insert in subdomain: %v", err)
	}

	got := s.emitWatchNewHosts(ctx, "round-1", "rank-t")
	// 20 visible + 1 truncated summary row.
	if len(got) != 21 {
		t.Fatalf("events count = %d, want 21 (20 visible + 1 truncated)", len(got))
	}
	if got[0].NewValue != "in.example.test" {
		t.Fatalf("first event host = %q, want in.example.test ranked ahead of out-of-scope 200-OK hosts", got[0].NewValue)
	}
}

func TestEmitWatchNewHostsNotificationMetadata(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('meta-t','example.test')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','meta-t','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO assets (id,target_id,value,asset_type,approval_status)
			VALUES ('a-1','meta-t','app.example.test','domain','approved')`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES
			('meta-t','app.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00'),
			('meta-t','other.example.test','2026-01-01 00:00:00','2026-01-02 00:00:00')`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES
			('s-app','meta-t','app.example.test',1),
			('s-other','meta-t','other.example.test',1)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	got := s.emitWatchNewHosts(ctx, "round-meta", "meta-t")
	if len(got) == 0 {
		t.Fatal("expected watch new_host events")
	}

	var metaRaw, severity string
	if err := s.db.QueryRow(`SELECT COALESCE(metadata,''), COALESCE(severity,'')
		FROM notifications WHERE target_id='meta-t' AND type='new_host'`).Scan(&metaRaw, &severity); err != nil {
		t.Fatalf("query new_host notification: %v", err)
	}
	if severity != "info" {
		t.Fatalf("severity = %q, want info", severity)
	}
	var meta struct {
		Source string   `json:"source"`
		Hosts  []string `json:"hosts"`
		Total  int      `json:"total"`
		TaskID string   `json:"task_id"`
	}
	if err := json.Unmarshal([]byte(metaRaw), &meta); err != nil {
		t.Fatalf("unmarshal metadata %q: %v", metaRaw, err)
	}
	if meta.Source != "watch" {
		t.Errorf("metadata.source = %q, want watch", meta.Source)
	}
	if len(meta.Hosts) != 1 || meta.Hosts[0] != "app.example.test" {
		t.Errorf("metadata.hosts = %v, want [app.example.test]", meta.Hosts)
	}
	if meta.Total != 1 || meta.TaskID != "round-meta" {
		t.Errorf("metadata total/task_id = %d/%q, want 1/round-meta", meta.Total, meta.TaskID)
	}
}

type scopeLandedRecorder struct {
	calls []struct {
		eventKey string
		summary  string
		hosts    []string
	}
}

func (r *scopeLandedRecorder) NotifyScanStarted(string, string, string)                          {}
func (r *scopeLandedRecorder) NotifyPhaseFinished(string, string, string, string, string, time.Duration, int, int) {}
func (r *scopeLandedRecorder) NotifyScanFinished(string, string, string, string, time.Duration, map[string]int) {}
func (r *scopeLandedRecorder) NotifyNewVuln(string, string, string, string, string, string, string) {}
func (r *scopeLandedRecorder) NotifyMonitorChange(string, string, string, string, string, string, string, ...string) {}
func (r *scopeLandedRecorder) NotifyHTTPStatus(string, string, string, string, string, string, string, string) {}
func (r *scopeLandedRecorder) NotifyProgramScope(string, string, string, string, string, string) {}
func (r *scopeLandedRecorder) NotifyWatchScanStarted(string, string, string)                     {}
func (r *scopeLandedRecorder) NotifyWatchScanFinished(string, string, string, string, time.Duration, map[string]int, string) {}
func (r *scopeLandedRecorder) NotifyNewHosts(string, string, []string, string)                   {}
func (r *scopeLandedRecorder) NotifyScopeLanded(eventKey, summary string, hosts []string) {
	r.calls = append(r.calls, struct {
		eventKey string
		summary  string
		hosts    []string
	}{eventKey: eventKey, summary: summary, hosts: append([]string(nil), hosts...)})
}

func TestFlushScopeLandingsSkipsRound1BaselineAndSendsRound2(t *testing.T) {
	s := newTestScheduler(t)
	rec := &scopeLandedRecorder{}
	s.SetNotifier(rec)
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO targets(id,domain,watch_only) VALUES('t-flush','flush.test',1)`,
		`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('p-flush','hackerone','p-flush','flush','Flush')`,
		`INSERT INTO project_programs(target_id,program_id) VALUES('t-flush','p-flush')`,
		`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type,is_wildcard) VALUES('a-flush','p-flush','ext-flush','*.flush.test','domain',1)`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	// Round 1 baseline landing -> announced=1, flushScopeLandings sends no alert.
	scanner.LandWatchScopeHosts(scanner.WithTaskID(ctx, "round-1"), s.db, "t-flush", []string{"one.flush.test"}, nil)
	s.flushScopeLandings()
	if len(rec.calls) != 0 {
		t.Fatalf("Round 1 NotifyScopeLanded calls = %d, want 0", len(rec.calls))
	}

	// Round 2 incremental landing -> announced=0, flushScopeLandings sends alert.
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,priority,modules,total) VALUES('round-1','t-flush','watch_scan','finished',1,'[]',2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE targets SET watch_scope_baselined=1 WHERE id='t-flush'`); err != nil {
		t.Fatal(err)
	}
	scanner.LandWatchScopeHosts(scanner.WithTaskID(ctx, "round-2"), s.db, "t-flush", []string{"one.flush.test", "two.flush.test"}, nil)
	s.flushScopeLandings()
	if len(rec.calls) != 1 {
		t.Fatalf("Round 2 NotifyScopeLanded calls = %d, want 1", len(rec.calls))
	}
	if len(rec.calls[0].hosts) != 1 || rec.calls[0].hosts[0] != "two.flush.test" {
		t.Fatalf("Round 2 NotifyScopeLanded hosts = %v, want [two.flush.test]", rec.calls[0].hosts)
	}
}
