package scheduler

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDiffWatchHTTPStatusAndTitleChange(t *testing.T) {
	before := map[string]watchHTTPSnapshot{
		"https://a.example": {URL: "https://a.example", StatusCode: 403, Title: "Forbidden"},
	}
	after := map[string]watchHTTPSnapshot{
		"https://a.example": {URL: "https://a.example", StatusCode: 200, Title: "OK"},
	}

	changes := diffWatchHTTP(before, after, true, false)
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want status_change + page_change", len(changes))
	}

	var status *watchChange
	for i := range changes {
		if changes[i].ChangeType == "status_change" {
			status = &changes[i]
		}
	}
	if status == nil {
		t.Fatal("status_change not produced")
	}
	if status.Severity != "medium" {
		t.Errorf("severity = %q, want medium", status.Severity)
	}
	if want := "status=403 title=Forbidden"; status.OldValue != want {
		t.Errorf("old_value = %q, want %q", status.OldValue, want)
	}
	if want := "status=200 title=OK"; status.NewValue != want {
		t.Errorf("new_value = %q, want %q", status.NewValue, want)
	}
	var meta struct {
		OldCode int `json:"old_code"`
		NewCode int `json:"new_code"`
	}
	if err := json.Unmarshal([]byte(status.Metadata), &meta); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if meta.OldCode != 403 || meta.NewCode != 200 {
		t.Errorf("metadata codes = %d/%d, want 403/200", meta.OldCode, meta.NewCode)
	}
}

func TestDiffWatchHTTPOtherChanges(t *testing.T) {
	base := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "OK", Server: "nginx", Technologies: "react, jquery"}

	title := base
	title.Title = "Welcome"
	got := diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: title}, true, false)
	if len(got) != 1 || got[0].ChangeType != "page_change" {
		t.Fatalf("title change: got %+v, want one page_change", got)
	}

	tech := base
	tech.Server = "apache"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: tech}, true, false)
	if len(got) != 1 || got[0].ChangeType != "tech_change" {
		t.Fatalf("server change: got %+v, want one tech_change", got)
	}

	redirect := base
	redirect.RedirectURL = "https://b.example"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: redirect}, true, false)
	if len(got) != 1 || got[0].ChangeType != "redirect_change" || got[0].Severity != "low" {
		t.Fatalf("redirect change: got %+v, want one low redirect_change", got)
	}

	// Removal is liveness state, not a detail row. diffWatchHTTP must stay silent.
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{}, true, false)
	if len(got) != 0 {
		t.Fatalf("removed url: got %+v, want no rows (no http_service_removed)", got)
	}

	// A new URL on a brand-new host is owned by the host emitter.
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{}, map[string]watchHTTPSnapshot{base.URL: base}, true, false)
	if len(got) != 0 {
		t.Fatalf("new url: got %+v, want no rows (no new_http_service)", got)
	}
}

func TestDiffWatchHTTPNewServiceOnKnownHost(t *testing.T) {
	base := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "OK"}
	newPort := watchHTTPSnapshot{URL: "https://a.example:8443/admin", StatusCode: 200, Title: "Admin"}

	before := map[string]watchHTTPSnapshot{base.URL: base}
	after := map[string]watchHTTPSnapshot{base.URL: base, newPort.URL: newPort}

	got := diffWatchHTTP(before, after, true, false)
	if len(got) != 0 {
		t.Fatalf("new service on known host: got %+v, want no rows", got)
	}
}

func TestDiffWatchHTTPIgnoresHostDiffAndCappedFlags(t *testing.T) {
	old := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 403, Title: "Same"}
	cur := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "Same"}
	added := watchHTTPSnapshot{URL: "https://new.example", StatusCode: 200, Title: "New"}
	evicted := watchHTTPSnapshot{URL: "https://zzz.example", StatusCode: 200, Title: "Old"}

	before := map[string]watchHTTPSnapshot{old.URL: old, evicted.URL: evicted}
	after := map[string]watchHTTPSnapshot{cur.URL: cur, added.URL: added}

	for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		got := diffWatchHTTP(before, after, flags[0], flags[1])
		if len(got) != 1 || got[0].ChangeType != "status_change" {
			t.Fatalf("flags %v: got %+v, want one status_change", flags, got)
		}
	}
}

func TestSnapshotsFromDatabase(t *testing.T) {
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

	httpSnap, err := snapshotWatchHTTP(ctx, s.db, "t1")
	if err != nil {
		t.Fatalf("snapshotWatchHTTP: %v", err)
	}
	got, ok := httpSnap["https://a.example"]
	if !ok || got.StatusCode != 403 || got.Title != "Forbidden" || got.Server != "nginx" || got.Technologies != "jquery, react" {
		t.Fatalf("http snapshot = %+v", got)
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

func TestInsertWatchRoundChangesSurvivesTaskDeletion(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status, priority, modules, total)
		VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`); err != nil {
		t.Fatalf("insert task: %v", err)
	}

	changes := []watchChange{{
		URL: "https://a.example", ChangeType: "status_change",
		OldValue: "status=403 title=Forbidden", NewValue: "status=200 title=OK",
		Severity: "medium", Metadata: `{"old_code":403,"new_code":200}`,
	}}
	s.insertWatchRoundChanges(ctx, "round-1", "t1", changes)

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE task_id='round-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after insert count = %d, err = %v", count, err)
	}

	if _, err := s.db.Exec(`DELETE FROM tasks WHERE id='round-1'`); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE task_id='round-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after task delete count = %d, err = %v, want 1 (no FK cascade)", count, err)
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
		AND first_alive_at IS NOT NULL AND announced_at IS NULL`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unannounced alive hosts = %d, err = %v, want 0", count, err)
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

func TestEmitWatchNewHostsSkipsDeadHosts(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('dead-t','example.test')`,
		`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
			VALUES ('round-0','dead-t','watch_scan','finished',1,'[]',1)`,
		`INSERT INTO watch_hosts (target_id,host,first_seen_at,first_alive_at) VALUES
			('dead-t','dead.example.test','2026-01-01 00:00:00',NULL)`,
		`INSERT INTO subdomains (id,target_id,subdomain,is_alive) VALUES ('s-dead','dead-t','dead.example.test',0)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	got := s.emitWatchNewHosts(ctx, "round-1", "dead-t")
	if len(got) != 0 {
		t.Fatalf("events = %+v, want none for a dead host", got)
	}
	var announced int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_hosts WHERE target_id='dead-t' AND announced_at IS NOT NULL`).Scan(&announced); err != nil {
		t.Fatal(err)
	}
	if announced != 0 {
		t.Fatalf("announced dead hosts = %d, want 0", announced)
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
