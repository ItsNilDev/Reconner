package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
)

type changesEnvelope struct {
	Data  []ChangeEntry `json:"data"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

type roundsEnvelope struct {
	Data  []WatchRound `json:"data"`
	Total int          `json:"total"`
}

func serveChanges(t *testing.T, h *Handler, sid, path string, vars map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.requireAuth(handler)(rec, req)
	return rec
}

func TestListChangesScopedToOwner(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)

	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-admin','t-admin','https://a','http_change','status=403 title=Forbidden','status=200 title=OK','high',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc-bob','t-bob','round-1','','new_subdomain','','b.example','medium','{"hosts":["b.example"]}',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity)
		VALUES ('n-global',NULL,'watch_failed','Round failed','ok','info')`)

	rec := serveChanges(t, h, bobSID, "/api/changes", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; body = %s", err, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, e := range env.Data {
		ids[e.ID] = true
	}
	if ids["mc-admin"] {
		t.Error("member saw another owner's monitoring change")
	}
	if !ids["wc-bob"] {
		t.Error("member did not see own new_subdomain")
	}
	if !ids["n-global"] {
		t.Error("member did not see target-less notice")
	}
	if env.Total != 2 {
		t.Errorf("total = %d, want 2", env.Total)
	}
}

func TestListChangesNotificationMetadataRoundTrip(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,metadata,created_at)
		VALUES ('n-scope','t1','bounty_scope_change','Scope changed','2 assets changed on one.example','medium',
		'{"hosts":["a.example","b.example"],"truncated":false,"total":2}','2026-03-01 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	rec := serveChanges(t, h, sid, "/api/changes?source=notification&target_id=t1", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 {
		t.Fatalf("rows = %d, want 1", len(env.Data))
	}
	row := env.Data[0]
	hosts, ok := row.Metadata["hosts"].([]any)
	if !ok || len(hosts) != 2 {
		t.Fatalf("metadata hosts = %v, want two entries", row.Metadata["hosts"])
	}
	if hosts[0] != "a.example" || hosts[1] != "b.example" {
		t.Fatalf("hosts = %v, want [a.example b.example]", hosts)
	}
	if row.Metadata["total"] != float64(2) {
		t.Fatalf("total = %v, want 2", row.Metadata["total"])
	}
}

func TestListTargetChangesForcesRoutedTarget(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t2','two.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t1','https://1','http_change','status=403 title=Forbidden','status=200 title=OK','low',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc2','t2','https://2','http_change','status=200 title=OK','status=404 title=Gone','low',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/targets/t1/changes?target_id=t2", map[string]string{"id": "t1"}, h.handleListTargetChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "mc1" {
		t.Fatalf("rows = %+v, want only mc1", env.Data)
	}
}

func TestListWatchRoundsChangeCount(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
		VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','round-1','https://1','status_change','a','b','low','{}',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc2','t1','round-1','https://2','page_change','a','b','low','{}',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/watch/rounds", nil, h.handleListWatchRounds)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env roundsEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "round-1" || env.Data[0].ChangeCount != 2 {
		t.Fatalf("rounds = %+v, want round-1 with 2 changes", env.Data)
	}
}

func TestListChangesFiltersAndPagination(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t1','https://1','http_change','status=403 title=Forbidden','status=200 title=OK','high','2026-01-01 00:00:00')`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-js','t1','https://j','js_change','a','b','medium','2026-02-02 00:00:00')`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','round-1','','new_subdomain','','new.example','medium','{"hosts":["new.example"]}','2026-02-01 00:00:00')`)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
		VALUES ('n1','t1','watch_failed','Round failed','oops','high','2026-03-01 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want []string
	}{
		{"category http", "/api/changes?category=http", []string{"mc1"}},
		{"category scripts", "/api/changes?category=scripts", []string{"mc-js"}},
		{"category assets", "/api/changes?category=assets", []string{"wc1"}},
		{"category alerts", "/api/changes?category=alerts", []string{"n1"}},
		{"severity high", "/api/changes?severity=high", []string{"mc1", "n1"}},
		{"source monitor", "/api/changes?source=monitor", []string{"mc1", "mc-js"}},
		{"source watch", "/api/changes?source=watch", []string{"wc1"}},
		{"source notification", "/api/changes?source=notification", []string{"n1"}},
		{"task id", "/api/changes?task_id=round-1", []string{"wc1"}},
		{"since", "/api/changes?since=2026-03-01", []string{"n1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			if len(env.Data) != len(tc.want) {
				t.Fatalf("ids = %+v, want %v", idsOf(env.Data), tc.want)
			}
			got := idsOf(env.Data)
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %q in %v", w, got)
				}
			}
		})
	}

	// Pagination: page 2 must skip the first row and the total must stay 4.
	rec := serveChanges(t, h, sid, "/api/changes?page=2&limit=1", nil, h.handleListChanges)
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Total != 4 || len(env.Data) != 1 {
		t.Fatalf("page 2: total = %d, rows = %d, want 4 and 1", env.Total, len(env.Data))
	}
	if env.Data[0].ID == "mc1" {
		t.Error("page 2 repeated the first row")
	}
}

func idsOf(rows []ChangeEntry) map[string]bool {
	ids := make(map[string]bool, len(rows))
	for _, row := range rows {
		ids[row.ID] = true
	}
	return ids
}

func TestListWatchRoundsIncludesOrphanedChanges(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	// No tasks row. The task was pruned at 90 days but the change survives.
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','old-round','https://1','status_change','a','b','low','{}','2026-01-01 00:00:00')`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc2','t1','old-round','https://2','page_change','a','b','low','{}','2026-01-02 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/watch/rounds", nil, h.handleListWatchRounds)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env roundsEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "old-round" || env.Data[0].ChangeCount != 2 {
		t.Fatalf("rounds = %+v, want one synthesized old-round with 2 changes", env.Data)
	}
	if env.Data[0].StartedAt != "2026-01-01 00:00:00" {
		t.Errorf("started_at = %q, want the earliest change time", env.Data[0].StartedAt)
	}
}

func postChanges(t *testing.T, h *Handler, sid, path string, body any, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.requireAuth(handler)(rec, req)
	return rec
}

func TestChangesSeenIsPerUserAndHonoursFilters(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t-admin','https://a','http_change','status=403 title=Forbidden','status=200 title=OK','high',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc2','t-bob','https://b','http_change','status=403 title=Forbidden','status=200 title=OK','high',CURRENT_TIMESTAMP)`)

	// Each user marks only their own change.
	rec := postChanges(t, h, adminSID, "/api/changes/seen", map[string]any{"ids": []string{"mc1"}, "seen": true}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin seen status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postChanges(t, h, bobSID, "/api/changes/seen", map[string]any{"ids": []string{"mc2"}, "seen": true}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob seen status = %d, body = %s", rec.Code, rec.Body.String())
	}

	readSeen := func(sid, path string) map[string]bool {
		t.Helper()
		rec := serveChanges(t, h, sid, path, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, e := range env.Data {
			out[e.ID] = e.Seen
		}
		return out
	}

	adminSeen := readSeen(adminSID, "/api/changes")
	if !adminSeen["mc1"] || adminSeen["mc2"] {
		t.Errorf("admin seen = %v, want mc1 read and mc2 unread", adminSeen)
	}
	bobSeen := readSeen(bobSID, "/api/changes")
	if len(bobSeen) != 1 || !bobSeen["mc2"] {
		t.Errorf("bob seen = %v, want only mc2 read", bobSeen)
	}

	// Owner scope, read-state join, and three filters in one query.
	bobFiltered := readSeen(bobSID, "/api/changes?category=http&severity=high&target_id=t-bob")
	if len(bobFiltered) != 1 || !bobFiltered["mc2"] {
		t.Errorf("bob filtered seen = %v, want only mc2 read", bobFiltered)
	}

	// Mark-all honours the target filter: only t-admin rows change.
	rec = postChanges(t, h, adminSID, "/api/changes/seen-all?target_id=t-admin", map[string]any{}, h.handleMarkAllChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("seen-all status = %d, body = %s", rec.Code, rec.Body.String())
	}
	adminSeen = readSeen(adminSID, "/api/changes")
	if !adminSeen["mc1"] || adminSeen["mc2"] {
		t.Errorf("after filtered mark-all, admin seen = %v, want mc1 read and mc2 unread", adminSeen)
	}
}

func TestListChangesNewFilters(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)

	// Deep status flip: http_change with status=NNN text, no metadata.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-deep','t1','https://deep','http_change','status=403 title=Forbidden','status=200 title=OK','medium','2026-01-01 00:00:00')`)
	// Watch status flip: the producer writes a detail row in watch_round_changes.
	// The feed widens the watch source for status-filtered requests only.
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc-watch','t1','task-1','https://watch','status_change','status=500 title=Error','status=200 title=OK','medium','{"old_code":500,"new_code":200}','2026-01-02 00:00:00')`)
	// Same status, title only.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-title','t1','https://title','http_change','status=200 title=Old','status=200 title=New','low','2026-01-03 00:00:00')`)
	// No status codes.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('wc-js','t1','https://js','js_change','a','b','medium','2026-01-04 00:00:00')`)
	// Removal row. The producer writes a URL in old_value, not a status token.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('wc-removed','t1','https://gone','http_service_removed','https://gone.example/app','','medium','2026-01-05 00:00:00')`)
	// Over-long code: status=2000 must not parse as 200 (trailing-space guard).
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-longcode','t1','https://long','http_change','status=2000 title=Big','status=2001 title=Big2','low','2026-01-06 00:00:00')`)
	// No prefix: 200 inside arbitrary text must not match (instr guard).
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-plain','t1','https://plain','http_change','abcdef200x','plain','low','2026-01-07 00:00:00')`)
	// Literal percent in a value, for LIKE escaping.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-pct','t1','https://pct','http_change','status=404 title=Not%Found','status=200 title=OK','low','2026-01-08 00:00:00')`)
	// Alert row, for multi-category.
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
		VALUES ('n-alert','t1','watch_failed','Round failed','oops','high','2026-01-09 00:00:00')`)

	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want []string
	}{
		{"status only", "/api/changes?status_only=1", []string{"mc-deep", "wc-watch", "mc-pct"}},
		{"class 2xx", "/api/changes?status_class=2", []string{"mc-deep", "wc-watch", "mc-title", "mc-pct"}},
		{"class 4xx", "/api/changes?status_class=4", []string{"mc-deep", "mc-pct"}},
		{"class 5xx", "/api/changes?status_class=5", []string{"wc-watch"}},
		{"code 200", "/api/changes?status_code=200", []string{"mc-deep", "wc-watch", "mc-title", "mc-pct"}},
		{"code 403", "/api/changes?status_code=403", []string{"mc-deep"}},
		{"multi category", "/api/changes?category=scripts,alerts", []string{"wc-js", "n-alert"}},
		{"all plus category", "/api/changes?category=all,http", []string{"mc-deep", "mc-title", "wc-removed", "wc-watch", "mc-longcode", "mc-plain", "mc-pct"}},
		{"q plain", "/api/changes?q=Forbidden", []string{"mc-deep"}},
		{"q literal percent", "/api/changes?q=%25", []string{"mc-pct"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			got := idsOf(env.Data)
			if len(got) != len(tc.want) {
				t.Fatalf("ids = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %q in %v", w, got)
				}
			}
			if env.Total != len(tc.want) {
				t.Errorf("total = %d, want %d", env.Total, len(tc.want))
			}
		})
	}
}

func TestListChangesNewFiltersMalformedValues(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-long','t1','https://long','http_change','status=2000 title=Big','status=2001 title=Big2','medium',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	// Malformed values are dropped, never truncated into a valid match.
	for _, q := range []string{
		"/api/changes?status_code=20",
		"/api/changes?status_code=2000",
		"/api/changes?status_code=abc",
		"/api/changes?status_class=9",
	} {
		rec := serveChanges(t, h, sid, q, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", q, rec.Code)
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if len(env.Data) != 1 {
			t.Errorf("%s: ids = %v, want the unfiltered row", q, idsOf(env.Data))
		}
	}

	// No truncation: a 2000-only row must not match a valid 200 filter.
	rec := serveChanges(t, h, sid, "/api/changes?status_code=200", nil, h.handleListChanges)
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 0 {
		t.Errorf("status_code=200 matched %v, want none (2000 must not truncate)", idsOf(env.Data))
	}
}

func TestListChangesNewFiltersScopedToOwner(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-admin','t-admin','https://a','http_change','status=403 title=Forbidden','status=200 title=OK','medium',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc-bob','t-bob','r1','','new_subdomain','','b.example','medium','{"hosts":["b.example"]}',CURRENT_TIMESTAMP)`)

	for _, q := range []string{
		"/api/changes?status_only=1",
		"/api/changes?status_code=200",
		"/api/changes?status_class=5",
		"/api/changes?q=Forbidden",
		"/api/changes?category=http,assets",
	} {
		rec := serveChanges(t, h, bobSID, q, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", q, rec.Code)
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		for _, e := range env.Data {
			if e.ID == "mc-admin" {
				t.Errorf("%s: member saw another owner's change", q)
			}
		}
	}
}

func TestListChangesStatusFiltersIgnoreFreeText(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	// A real deep status flip: the only row that should match.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-real','t1','https://real','http_change','status=404 title=Missing','status=200 title=OK','medium',CURRENT_TIMESTAMP)`)
	// A bell notice whose free text contains a status token. Its change type is
	// not status-bearing, so it must not match any status filter.
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
		VALUES ('n-text','t1','monitor_failed','Scan failed','upstream replied status=404 title=Missing','high',CURRENT_TIMESTAMP)`)
	// A bell that mirrors a real change type. It is outside the notification
	// allow-list, so it never reaches the feed at all.
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
		VALUES ('n-mirror','t1','http_change','Status changed','https://mirror — status=404 title=Missing','medium',CURRENT_TIMESTAMP)`)
	// A removal row carrying a status token in old_value. It is excluded by the
	// explicit http_service_removed clause in each status filter.
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('wc-removed','t1','https://gone','http_service_removed','status=404 title=Missing','','medium',CURRENT_TIMESTAMP)`)

	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"/api/changes?status_code=404",
		"/api/changes?status_class=4",
		"/api/changes?status_only=1",
	} {
		rec := serveChanges(t, h, sid, q, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", q, rec.Code)
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		got := idsOf(env.Data)
		if len(got) != 1 || !got["mc-real"] {
			t.Errorf("%s: ids = %v, want only mc-real (free text must not match)", q, got)
		}
	}
}

func TestListChangesCategoryMalformed(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t1','https://a','http_change','a','b','medium',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	// A non-empty category value with no valid token must match nothing, not
	// silently return the unfiltered feed.
	for _, q := range []string{
		"/api/changes?category=,,,",
		"/api/changes?category=garbage",
	} {
		rec := serveChanges(t, h, sid, q, nil, h.handleListChanges)
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if len(env.Data) != 0 {
			t.Errorf("%s: ids = %v, want none", q, idsOf(env.Data))
		}
	}
	// "all" still means no filter.
	rec := serveChanges(t, h, sid, "/api/changes?category=all", nil, h.handleListChanges)
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 {
		t.Errorf("category=all: ids = %v, want the row", idsOf(env.Data))
	}
}

func TestChangesFeedSourceAllowLists(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO bounty_programs (id, provider, external_id, handle, name)
		VALUES ('p1','intigriti','ext-1','program-one','Program One')`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-any','t1','https://1','http_change','a','b','low','2026-04-01 00:00:00')`)

	// Only new_subdomain reaches the feed. Detail and removal rows stay in the
	// audit table and are reachable through the rounds endpoint, not the feed.
	watchRows := []string{
		`'wc-new','t1','round-1','','new_subdomain','','new.example','medium','{}','2026-04-02 00:00:00'`,
		`'wc-detail','t1','round-1','','status_change','a','b','low','{}','2026-04-02 00:00:00'`,
		`'wc-removed','t1','round-1','','http_service_removed','https://gone','','medium','{}','2026-04-02 00:00:00'`,
	}
	for _, row := range watchRows {
		stmt := `INSERT INTO watch_round_changes
			(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES (` + row + `)`
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("insert watch row: %v", err)
		}
	}

	allowed := []string{
		"n-watch-failed:watch_failed",
		"n-watch-kind:watch_kind_conflict",
		"n-monitor-failed:monitor_failed",
		"n-escalation:monitor_escalation_started",
		"n-auto-paused:scan_auto_paused",
		"n-bounty-scope:bounty_scope_change",
		"n-new-host-allowed:new_host",
	}
	blocked := []string{
		"n-scope-landed:scope_landed",
		"n-catalog-sync:catalog_sync",
		"n-new-host:new_subdomain",
	}
	for _, spec := range append(append([]string{}, allowed...), blocked...) {
		parts := bytes.SplitN([]byte(spec), []byte(":"), 2)
		stmt := `INSERT INTO notifications (id,target_id,type,title,created_at) VALUES ('` +
			string(parts[0]) + `','t1','` + string(parts[1]) + `','bell','2026-04-03 00:00:00')`
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("insert notification: %v", err)
		}
	}

	// Program scope rows come from bounty_scope_events: added -> scope_landed,
	// modified -> scope_modified, removed -> scope_removed. Other event types
	// stay out of the feed.
	scopeRows := []string{
		`'se-added','t1','p1','added','new.example'`,
		`'se-modified','t1','p1','modified','new.example'`,
		`'se-removed','t1','p1','removed','new.example'`,
		`'se-other','t1','p1','re_eligible','new.example'`,
	}
	for _, row := range scopeRows {
		stmt := `INSERT INTO bounty_scope_events
			(id,target_id,program_id,event_type,identifier,new_json,detected_at)
			VALUES (` + row + `,'{"value":"new.example"}','2026-04-04 00:00:00')`
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("insert scope row: %v", err)
		}
	}

	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	wantAll := []string{
		"mc-any", "wc-new", "wc-detail", "wc-removed", "n-watch-failed", "n-watch-kind", "n-monitor-failed",
		"n-escalation", "n-auto-paused", "n-bounty-scope", "n-new-host-allowed", "se-added", "se-modified", "se-removed",
	}
	cases := []struct {
		name string
		path string
		want []string
	}{
		{"all", "/api/changes", wantAll},
		{"source monitor", "/api/changes?source=monitor", []string{"mc-any"}},
		{"source watch", "/api/changes?source=watch", []string{"wc-new", "wc-detail", "wc-removed"}},
		{"source notification", "/api/changes?source=notification", []string{
			"n-watch-failed", "n-watch-kind", "n-monitor-failed", "n-escalation", "n-auto-paused", "n-bounty-scope", "n-new-host-allowed",
		}},
		{"source bounty", "/api/changes?source=bounty", []string{"se-added", "se-modified", "se-removed"}},
		{"category assets", "/api/changes?category=assets", []string{"wc-new", "n-new-host-allowed", "se-added", "se-modified", "se-removed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			got := idsOf(env.Data)
			if len(got) != len(tc.want) {
				t.Fatalf("ids = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %q in %v", w, got)
				}
			}
			if env.Total != len(tc.want) {
				t.Errorf("total = %d, want %d", env.Total, len(tc.want))
			}
		})
	}

	// Alert types carry the alerts category. Blocked notification types never
	// reach the feed under any category.
	rec := serveChanges(t, h, sid, "/api/changes?category=alerts", nil, h.handleListChanges)
	var alerts changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatal(err)
	}
	alertIDs := idsOf(alerts.Data)
	for _, id := range []string{"n-watch-failed", "n-watch-kind", "n-monitor-failed", "n-escalation", "n-auto-paused"} {
		if !alertIDs[id] {
			t.Errorf("missing alert %q in %v", id, alertIDs)
		}
	}
	for _, id := range []string{"n-scope-landed", "n-catalog-sync", "n-new-host"} {
		if alertIDs[id] {
			t.Errorf("blocked notification %q leaked into alerts feed: %v", id, alertIDs)
		}
	}

	// Scope rows carry source=bounty, mapped change types, and metadata from
	// the program asset JSON.
	rec = serveChanges(t, h, sid, "/api/changes?source=bounty", nil, h.handleListChanges)
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, row := range env.Data {
		if row.Source != "bounty" || row.Category != "assets" {
			t.Errorf("%s: source = %q, category = %q; want bounty/assets", row.ID, row.Source, row.Category)
		}
		types[row.ID] = row.ChangeType
		if row.ID == "se-added" && row.Metadata["value"] != "new.example" {
			t.Errorf("se-added metadata = %+v, want value=new.example", row.Metadata)
		}
	}
	// Event type and decision state stay separate. A pending addition is still
	// an addition; pending state is returned in scope_status.
	if types["se-added"] != "scope_landed" || types["se-modified"] != "scope_modified" || types["se-removed"] != "scope_removed" {
		t.Errorf("scope change types = %v, want landed/modified/removed", types)
	}
	for _, row := range env.Data {
		if row.ID == "se-added" && row.ScopeStatus != "pending" {
			t.Errorf("se-added scope_status=%q, want pending", row.ScopeStatus)
		}
	}
}

func TestChangesFeedOwnerScopingAllSources(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)
	h.db.Exec(`INSERT INTO bounty_programs (id, provider, external_id, handle, name)
		VALUES ('p1','intigriti','ext-1','program-one','Program One')`)

	stmts := []string{
		`INSERT INTO monitoring_changes (id,target_id,url,change_type,detected_at)
			VALUES ('mc-admin','t-admin','https://a','http_change',CURRENT_TIMESTAMP)`,
		`INSERT INTO monitoring_changes (id,target_id,url,change_type,detected_at)
			VALUES ('mc-bob','t-bob','https://b','http_change',CURRENT_TIMESTAMP)`,
		`INSERT INTO watch_round_changes (id,target_id,task_id,change_type,detected_at)
			VALUES ('wc-admin','t-admin','r1','new_subdomain',CURRENT_TIMESTAMP)`,
		`INSERT INTO watch_round_changes (id,target_id,task_id,change_type,detected_at)
			VALUES ('wc-bob','t-bob','r2','new_subdomain',CURRENT_TIMESTAMP)`,
		`INSERT INTO bounty_scope_events (id,target_id,program_id,event_type,identifier,detected_at)
			VALUES ('se-admin','t-admin','p1','added','a.example',CURRENT_TIMESTAMP)`,
		`INSERT INTO bounty_scope_events (id,target_id,program_id,event_type,identifier,detected_at)
			VALUES ('se-bob','t-bob','p1','modified','b.example',CURRENT_TIMESTAMP)`,
		`INSERT INTO notifications (id,target_id,type,title,created_at)
			VALUES ('n-admin','t-admin','watch_failed','failed',CURRENT_TIMESTAMP)`,
		`INSERT INTO notifications (id,target_id,type,title,created_at)
			VALUES ('n-bob','t-bob','monitor_failed','failed',CURRENT_TIMESTAMP)`,
		`INSERT INTO notifications (id,target_id,type,title,created_at)
			VALUES ('n-global',NULL,'watch_failed','failed',CURRENT_TIMESTAMP)`,
	}
	for _, stmt := range stmts {
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	rec := serveChanges(t, h, bobSID, "/api/changes", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	got := idsOf(env.Data)
	want := []string{"mc-bob", "wc-bob", "se-bob", "n-bob", "n-global"}
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("missing %q in %v", id, got)
		}
	}
	for _, id := range []string{"mc-admin", "wc-admin", "se-admin", "n-admin"} {
		if got[id] {
			t.Errorf("member saw another owner's row %q", id)
		}
	}
	if env.Total != len(want) {
		t.Errorf("total = %d, want %d", env.Total, len(want))
	}
}

func TestStatusCodeToken(t *testing.T) {
	valid := map[string]int{"200": 200, "403": 403, "599": 599, "100": 100}
	for in, want := range valid {
		if got, ok := statusCodeToken(in); !ok || got != want {
			t.Errorf("statusCodeToken(%q) = %d,%v want %d,true", in, got, ok, want)
		}
	}
	for _, in := range []string{"+200", "0200", "20", "2000", "abc", "60x", ""} {
		if got, ok := statusCodeToken(in); ok {
			t.Errorf("statusCodeToken(%q) = %d,true want false", in, got)
		}
	}
}

func TestParseChangesSince(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"2026-11-18":           "2026-11-18 00:00:00",
		"2026-11-18 10:20:30":  "2026-11-18 10:20:30",
		"2026-11-18T10:20:30Z": "2026-11-18 10:20:30",
	}
	for in, want := range cases {
		if got := parseChangesSince(in); got != want {
			t.Errorf("parseChangesSince(%q) = %q, want %q", in, got, want)
		}
	}
}

// Watch scope landings are their own feed origin. A landing keeps its original
// event type, and a later loss of eligibility is a separate historical event.
func TestChangesFeedIncludesWatchScopeHistory(t *testing.T) {
	h, _ := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, bob.ID)
	for _, row := range []string{
		`'ws-landed','t1','p1','a.example','landed','a1','{"task_id":"round-9"}','2026-05-01 00:00:00'`,
		`'ws-lost','t1','p1','a.example','out_of_scope','a1','{"out_of_scope":1}','2026-05-02 00:00:00'`,
	} {
		stmt := `INSERT INTO watch_scope_events
			(id,target_id,program_id,identifier,event_type,asset_id,metadata,detected_at)
			VALUES (` + row + `)`
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("insert watch scope event: %v", err)
		}
	}

	rec := serveChanges(t, h, sid, "/api/changes?target_id=t1&source=watch_scope", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []ChangeEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	types := map[string]ChangeEntry{}
	for _, row := range resp.Data {
		types[row.ID] = row
	}
	landed, ok := types["ws-landed"]
	if !ok || landed.ChangeType != "scope_landed" || landed.Source != "watch_scope" || landed.TaskID != "round-9" {
		t.Fatalf("landing = %+v, want watch_scope/scope_landed/round-9", landed)
	}
	lost, ok := types["ws-lost"]
	if !ok || lost.ChangeType != "out_of_scope" {
		t.Fatalf("loss = %+v, want out_of_scope", lost)
	}
}

func TestChangesFeedReturnsNumericStatusColumns(t *testing.T) {
	h, _ := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, bob.ID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
		VALUES ('mc-1','t1','https://a.example','status_change','status=403 title=Forbidden','status=200 title=OK','medium',403,200,'2026-06-01 00:00:00')`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
		VALUES ('wc-1','t1','round-1','https://b.example','status_change','status=200 title=OK','status=403 title=Forbidden','medium',200,403,'2026-06-02 00:00:00')`)
	rec := serveChanges(t, h, sid, "/api/changes?status_only=1", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	got := map[string][2]int{}
	for _, e := range env.Data {
		got[e.ID] = [2]int{e.OldStatus, e.NewStatus}
	}
	if got["mc-1"] != [2]int{403, 200} || got["wc-1"] != [2]int{200, 403} {
		t.Fatalf("numeric status columns = %v, want mc=403/200 wc=200/403", got)
	}
}

// hide_seen must remove read rows before COUNT and LIMIT run. Otherwise a page
// of unread rows can hide a stale seen row, and the total still counts it.
func TestListChangesHideSeenExcludesRowsBeforeCountAndPagination(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)
	for _, row := range []string{
		`'mc-seen','t-admin','https://a','http_change','2026-01-01 00:00:00'`,
		`'mc-open','t-admin','https://b','http_change','2026-01-02 00:00:00'`,
		`'mc-bob','t-bob','https://c','http_change','2026-01-03 00:00:00'`,
	} {
		if _, err := h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,detected_at)
			VALUES (` + row + `)`); err != nil {
			t.Fatal(err)
		}
	}
	// Read state is per user. Admin read mc-seen; bob read mc-bob.
	for _, mark := range []struct {
		id  string
		uid int64
	}{{"mc-seen", adminID}, {"mc-bob", bob.ID}} {
		if _, err := h.db.Exec(`INSERT INTO change_seen (change_id,user_id,seen_at) VALUES (?,?,'2026-01-04 00:00:00')`, mark.id, mark.uid); err != nil {
			t.Fatal(err)
		}
	}

	read := func(sid, path string) changesEnvelope {
		t.Helper()
		rec := serveChanges(t, h, sid, path, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env
	}

	// Without hide_seen the seen row is present for both callers.
	all := read(adminSID, "/api/changes")
	if all.Total != 3 || !idsOf(all.Data)["mc-seen"] {
		t.Fatalf("admin unfiltered total=%d ids=%v, want 3 including mc-seen", all.Total, idsOf(all.Data))
	}
	bobAll := read(bobSID, "/api/changes")
	if bobAll.Total != 1 || !idsOf(bobAll.Data)["mc-bob"] {
		t.Fatalf("bob unfiltered total=%d ids=%v, want only mc-bob", bobAll.Total, idsOf(bobAll.Data))
	}

	// With hide_seen the seen row is gone before count and pagination.
	hidden := read(adminSID, "/api/changes?hide_seen=1&limit=1")
	if hidden.Total != 2 {
		t.Fatalf("admin hide_seen total=%d, want 2", hidden.Total)
	}
	if ids := idsOf(hidden.Data); len(ids) != 1 || ids["mc-seen"] {
		t.Fatalf("admin hide_seen ids=%v, want one row that is not mc-seen", ids)
	}
	bobHidden := read(bobSID, "/api/changes?hide_seen=1")
	if bobHidden.Total != 0 || len(bobHidden.Data) != 0 {
		t.Fatalf("bob hide_seen total=%d rows=%d, want 0 and 0", bobHidden.Total, len(bobHidden.Data))
	}
}

func TestChangesDefaultViewSQLAndFiltering(t *testing.T) {
	h, adminID := newIsoHandler(t)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, []any{adminID}},
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t2','two.example',?)`, []any{adminID}},
		{`INSERT INTO bounty_programs (id, provider, external_id, handle, name) VALUES ('p1','intigriti','ext-1','p1','Program')`, nil},
		// Included in default_view on t1:
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-sub','t1','r1','','new_subdomain','','sub.one.example','medium',0,0,'2026-06-01 00:00:01')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-status','t1','r1','https://one.example','status_change','200','403','medium',200,403,'2026-06-01 00:00:02')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http','t1','https://a.one.example','http_change','status=200 title=OK','status=403 title=Forbidden','medium',200,403,'2026-06-01 00:00:03')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-page','t1','https://b.one.example','page_change','status=200 title=OK','status=403 title=Forbidden','medium',0,0,'2026-06-01 00:00:04')`, nil},
		{`INSERT INTO bounty_scope_events (id,target_id,program_id,event_type,identifier,detected_at)
			VALUES ('se-add','t1','p1','added','api.one.example','2026-06-01 00:00:05')`, nil},
		{`INSERT INTO watch_scope_events (id,target_id,program_id,identifier,event_type,asset_id,metadata,detected_at)
			VALUES ('ws-oos','t1','p1','old.one.example','out_of_scope','a1','{}','2026-06-01 00:00:06')`, nil},
		{`INSERT INTO notifications (id,target_id,type,title,body,metadata,created_at)
			VALUES ('n-host-deep','t1','new_host','New host','deep.one.example','{"source":"monitor"}','2026-06-01 00:00:07')`, nil},
		// Excluded from default_view on t1:
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-same','t1','https://c.one.example','http_change','status=200 title=Old','status=200 title=New','low',200,200,'2026-06-01 00:00:08')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-js','t1','https://d.one.example/app.js','js_change','a','b','low','2026-06-01 00:00:09')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-same','t1','r1','https://same.one.example','status_change','status=200 title=A','status=200 title=B','low',200,200,'2026-06-01 00:00:10')`, nil},
		{`INSERT INTO notifications (id,target_id,type,title,body,metadata,created_at)
			VALUES ('n-host-watch','t1','new_host','New host','watch.one.example','{"source":"watch"}','2026-06-01 00:00:11')`, nil},
		{`INSERT INTO notifications (id,target_id,type,title,body,metadata,created_at)
			VALUES ('n-alert','t1','watch_failed','Failed','err','{}','2026-06-01 00:00:12')`, nil},
		// Included in default_view on t2 (for forced-target isolation check):
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('wc-t2','t2','r2','','new_subdomain','','sub.two.example','medium','2026-06-01 00:00:13')`, nil},
	} {
		if _, err := h.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("seed %s: %v", q.sql, err)
		}
	}

	// 1. Global default_view=1
	rec := serveChanges(t, h, sid, "/api/changes?default_view=1", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("global default_view status=%d body=%s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	got := idsOf(env.Data)
	wantGlobal := []string{"wc-sub", "wc-status", "mc-http", "mc-page", "se-add", "ws-oos", "n-host-deep", "wc-t2"}
	if len(got) != len(wantGlobal) || env.Total != len(wantGlobal) {
		t.Fatalf("global default_view ids=%v total=%d, want %v", got, env.Total, wantGlobal)
	}
	for _, id := range wantGlobal {
		if !got[id] {
			t.Errorf("global default_view missing %q in %v", id, got)
		}
	}
	for _, excluded := range []string{"mc-same", "mc-js", "wc-same", "n-host-watch", "n-alert"} {
		if got[excluded] {
			t.Errorf("global default_view unexpectedly included %q", excluded)
		}
	}

	// Watch-sourced new_host notification is excluded even without default_view.
	recAll := serveChanges(t, h, sid, "/api/changes?source=notification", nil, h.handleListChanges)
	if recAll.Code != http.StatusOK {
		t.Fatalf("notifications list status=%d body=%s", recAll.Code, recAll.Body.String())
	}
	var envAll changesEnvelope
	if err := json.Unmarshal(recAll.Body.Bytes(), &envAll); err != nil {
		t.Fatal(err)
	}
	if idsOf(envAll.Data)["n-host-watch"] {
		t.Errorf("watch-sourced notification n-host-watch leaked into changes feed")
	}

	// 2. Forced-target isolation: route id=t1 wins over ?target_id=t2.
	recTarget := serveChanges(t, h, sid, "/api/targets/t1/changes?default_view=1&target_id=t2", map[string]string{"id": "t1"}, h.handleListTargetChanges)
	if recTarget.Code != http.StatusOK {
		t.Fatalf("target default_view status=%d body=%s", recTarget.Code, recTarget.Body.String())
	}
	var envTarget changesEnvelope
	if err := json.Unmarshal(recTarget.Body.Bytes(), &envTarget); err != nil {
		t.Fatal(err)
	}
	gotTarget := idsOf(envTarget.Data)
	if gotTarget["wc-t2"] || len(gotTarget) != len(wantGlobal)-1 {
		t.Fatalf("forced target default_view ids=%v, want only t1 rows", gotTarget)
	}

	// 3. Mark-all-read with default_view=1 only marks default_view rows.
	recMark := postChanges(t, h, sid, "/api/changes/seen-all?default_view=1&target_id=t1", map[string]any{}, h.handleMarkAllChangesSeen)
	if recMark.Code != http.StatusOK {
		t.Fatalf("mark-all default_view status=%d body=%s", recMark.Code, recMark.Body.String())
	}
	recAfter := serveChanges(t, h, sid, "/api/changes", nil, h.handleListChanges)
	if recAfter.Code != http.StatusOK {
		t.Fatalf("after mark-all status=%d body=%s", recAfter.Code, recAfter.Body.String())
	}
	var envAfter changesEnvelope
	if err := json.Unmarshal(recAfter.Body.Bytes(), &envAfter); err != nil {
		t.Fatal(err)
	}
	seenByID := map[string]bool{}
	for _, row := range envAfter.Data {
		seenByID[row.ID] = row.Seen
	}
	if !seenByID["mc-http"] || !seenByID["wc-status"] || !seenByID["n-host-deep"] {
		t.Errorf("expected t1 default_view rows marked seen: %v", seenByID)
	}
	if seenByID["mc-same"] || seenByID["mc-js"] || seenByID["wc-t2"] || seenByID["n-alert"] {
		t.Errorf("non-matching rows unexpectedly marked seen: %v", seenByID)
	}
}

func TestChangesAndBellReadStateSync(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("sync-bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("sync-bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t-sync','sync.example',?)`, []any{adminID}},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-1','t-sync','https://1.sync.example','http_change','status=200 title=A','status=403 title=B','medium',200,403,'2026-06-01 00:00:01')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-2','t-sync','https://2.sync.example','http_change','status=200 title=A','status=404 title=C','medium',200,404,'2026-06-01 00:00:02')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-3','t-sync','https://3.sync.example','http_change','status=200 title=A','status=500 title=D','high',200,500,'2026-06-01 00:00:03')`, nil},
		// Notification linked via change_id to mc-1:
		{`INSERT INTO notifications (id,target_id,type,title,body,is_read,change_id,created_at)
			VALUES ('n-mc1','t-sync','http_change','Changed','status=403',0,'mc-1','2026-06-01 00:00:01')`, nil},
		// Notification linked via change_id to mc-2:
		{`INSERT INTO notifications (id,target_id,type,title,body,is_read,change_id,created_at)
			VALUES ('n-mc2','t-sync','http_change','Changed','status=404',0,'mc-2','2026-06-01 00:00:02')`, nil},
		// Notification linked via change_id to mc-3:
		{`INSERT INTO notifications (id,target_id,type,title,body,is_read,change_id,created_at)
			VALUES ('n-mc3','t-sync','http_change','Changed','status=500',0,'mc-3','2026-06-01 00:00:03')`, nil},
		// Direct notification row that appears in Changes feed itself:
		{`INSERT INTO notifications (id,target_id,type,title,body,is_read,created_at)
			VALUES ('n-alert','t-sync','monitor_failed','Monitor failed','timeout',0,'2026-06-01 00:00:04')`, nil},
		// Target-less shared notification for per-user isolation check:
		{`INSERT INTO notifications (id,target_id,type,title,body,is_read,created_at)
			VALUES ('n-shared',NULL,'watch_failed','Global notice','info',0,'2026-06-01 00:00:05')`, nil},
	} {
		if _, err := h.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("seed %s: %v", q.sql, err)
		}
	}

	notifRead := func(uid int64, notifID string) bool {
		t.Helper()
		var n int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id=? AND user_id=?`, notifID, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	changeSeen := func(uid int64, changeID string) bool {
		t.Helper()
		var n int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM change_seen WHERE change_id=? AND user_id=?`, changeID, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	// 1. Changes -> Bell: marking mc-1 seen mirrors to notification n-mc1 via change_id.
	rec := postChanges(t, h, adminSID, "/api/changes/seen", map[string]any{"ids": []string{"mc-1"}, "seen": true}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("set seen status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !changeSeen(adminID, "mc-1") || !notifRead(adminID, "n-mc1") {
		t.Fatalf("mc-1 seen sync failed: changeSeen=%v notifRead=%v", changeSeen(adminID, "mc-1"), notifRead(adminID, "n-mc1"))
	}

	// Unmarking mc-1 removes n-mc1 from notification_reads.
	rec = postChanges(t, h, adminSID, "/api/changes/seen", map[string]any{"ids": []string{"mc-1"}, "seen": false}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("set unseen status=%d body=%s", rec.Code, rec.Body.String())
	}
	if changeSeen(adminID, "mc-1") || notifRead(adminID, "n-mc1") {
		t.Fatalf("mc-1 unseen sync failed: changeSeen=%v notifRead=%v", changeSeen(adminID, "mc-1"), notifRead(adminID, "n-mc1"))
	}

	// 2. Bell -> Changes (specific ID): marking n-mc2 read mirrors both n-mc2 and change_id mc-2 into change_seen.
	rec = postChanges(t, h, adminSID, "/api/notifications/read", map[string]any{"ids": []string{"n-mc2"}}, h.handleMarkNotificationsRead)
	if rec.Code != http.StatusOK {
		t.Fatalf("bell mark single status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !notifRead(adminID, "n-mc2") || !changeSeen(adminID, "n-mc2") || !changeSeen(adminID, "mc-2") {
		t.Fatalf("bell single sync failed: notifRead=%v changeSeen(n)=%v changeSeen(mc)=%v",
			notifRead(adminID, "n-mc2"), changeSeen(adminID, "n-mc2"), changeSeen(adminID, "mc-2"))
	}

	// 3. Bell -> Changes (bulk bucket): marking deep bucket read syncs n-mc3 -> mc-3 and n-alert.
	rec = postChanges(t, h, adminSID, "/api/notifications/read", map[string]any{"type": "deep"}, h.handleMarkNotificationsRead)
	if rec.Code != http.StatusOK {
		t.Fatalf("bell mark bulk status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !notifRead(adminID, "n-mc3") || !changeSeen(adminID, "mc-3") || !changeSeen(adminID, "n-alert") {
		t.Fatalf("bell bulk sync failed: notifRead(n-mc3)=%v changeSeen(mc-3)=%v changeSeen(n-alert)=%v",
			notifRead(adminID, "n-mc3"), changeSeen(adminID, "mc-3"), changeSeen(adminID, "n-alert"))
	}
	// watch_failed is not in deep bucket so n-shared stays unread.
	if notifRead(adminID, "n-shared") || changeSeen(adminID, "n-shared") {
		t.Fatalf("deep bucket bulk read leaked to n-shared")
	}

	// 4. Changes Mark-all-seen (with hide_seen=1) mirrors remaining unread rows (including change_id & direct notif) to bell.
	// First clear mc-1 & n-mc1 to be sure they're unread, then mark all seen with hide_seen=1.
	rec = postChanges(t, h, adminSID, "/api/changes/seen-all?hide_seen=1", map[string]any{}, h.handleMarkAllChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("changes seen-all status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !changeSeen(adminID, "n-shared") || !notifRead(adminID, "n-shared") {
		t.Fatalf("seen-all failed to sync n-shared: changeSeen=%v notifRead=%v", changeSeen(adminID, "n-shared"), notifRead(adminID, "n-shared"))
	}
	if !changeSeen(adminID, "mc-1") || !notifRead(adminID, "n-mc1") {
		t.Fatalf("seen-all failed to sync mc-1 -> n-mc1: changeSeen=%v notifRead=%v", changeSeen(adminID, "mc-1"), notifRead(adminID, "n-mc1"))
	}

	// 5. Per-user isolation: bob still sees n-shared unread in both surfaces.
	if notifRead(bob.ID, "n-shared") || changeSeen(bob.ID, "n-shared") {
		t.Fatalf("admin sync leaked read state to bob")
	}
	bobRec := serveChanges(t, h, bobSID, "/api/changes?hide_seen=1", nil, h.handleListChanges)
	if bobRec.Code != http.StatusOK {
		t.Fatalf("bob list status=%d body=%s", bobRec.Code, bobRec.Body.String())
	}
	var bobEnv changesEnvelope
	if err := json.Unmarshal(bobRec.Body.Bytes(), &bobEnv); err != nil {
		t.Fatal(err)
	}
	if !idsOf(bobEnv.Data)["n-shared"] {
		t.Fatalf("bob should still see unread n-shared, got %v", idsOf(bobEnv.Data))
	}
}

func TestListChangesContentChangeCategory(t *testing.T) {
	h, adminID := newIsoHandler(t)
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, []any{adminID}},
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t2','two.example',?)`, []any{adminID}},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-content-1','t1','https://one.example/page','content_change','hash=aaa','hash=bbb','low',CURRENT_TIMESTAMP)`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-content-2','t2','https://two.example/page','content_change','hash=ccc','hash=ddd','low',CURRENT_TIMESTAMP)`, nil},
	} {
		if _, err := h.db.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/changes?category=http&target_id=t1", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "mc-content-1" || env.Data[0].Category != "http" {
		t.Fatalf("got %+v, want single mc-content-1 with category http", env.Data)
	}
}

func TestChangesCategoryHostsAndScope(t *testing.T) {
	h, adminID := newIsoHandler(t)
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, []any{adminID}},
		{`INSERT INTO bounty_programs (id, provider, external_id, handle, name) VALUES ('p1','intigriti','ext-1','p1','Program')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES ('wc-host','t1','r1','','new_subdomain','','sub.one.example','medium','{"hosts":["sub.one.example"]}','2026-06-01 00:00:01')`, nil},
		{`INSERT INTO notifications (id,target_id,type,title,body,metadata,created_at)
			VALUES ('n-host','t1','new_host','New host','deep.one.example','{"source":"monitor"}','2026-06-01 00:00:02')`, nil},
		{`INSERT INTO bounty_scope_events (id,target_id,program_id,event_type,identifier,detected_at)
			VALUES ('se-bounty','t1','p1','added','api.one.example','2026-06-01 00:00:03')`, nil},
		{`INSERT INTO watch_scope_events (id,target_id,program_id,identifier,event_type,asset_id,metadata,detected_at)
			VALUES ('ws-scope','t1','p1','old.one.example','landed','a1','{}','2026-06-01 00:00:04')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http','t1','https://one.example','http_change','status=403 title=Forbidden','status=200 title=OK','high',403,200,'2026-06-01 00:00:05')`, nil},
	} {
		if _, err := h.db.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want map[string]bool
	}{
		{
			name: "category=hosts returns watch new_subdomain and deep new_host only",
			path: "/api/changes?category=hosts",
			want: map[string]bool{"wc-host": true, "n-host": true},
		},
		{
			name: "category=scope returns bounty and watch_scope only",
			path: "/api/changes?category=scope",
			want: map[string]bool{"se-bounty": true, "ws-scope": true},
		},
		{
			name: "category=hosts,http combines virtual and standard categories with OR",
			path: "/api/changes?category=hosts,http",
			want: map[string]bool{"wc-host": true, "n-host": true, "mc-http": true},
		},
		{
			name: "category=hosts,http&source=watch intersects category and source",
			path: "/api/changes?category=hosts,http&source=watch",
			want: map[string]bool{"wc-host": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := idsOf(env.Data)
			if len(got) != len(tc.want) {
				t.Fatalf("got ids %v (total=%d), want %v", got, env.Total, tc.want)
			}
			for id := range tc.want {
				if !got[id] {
					t.Fatalf("missing %q in %v", id, got)
				}
			}
		})
	}

	t.Run("seen-all with category=hosts leaves non-hosts unseen", func(t *testing.T) {
		rec := postChanges(t, h, sid, "/api/changes/seen-all?category=hosts", map[string]any{}, h.handleMarkAllChangesSeen)
		if rec.Code != http.StatusOK {
			t.Fatalf("seen-all status = %d, body = %s", rec.Code, rec.Body.String())
		}
		listRec := serveChanges(t, h, sid, "/api/changes", nil, h.handleListChanges)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(listRec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		seen := map[string]bool{}
		for _, e := range env.Data {
			seen[e.ID] = e.Seen
		}
		for _, id := range []string{"wc-host", "n-host"} {
			if !seen[id] {
				t.Errorf("expected %s to be marked seen, got seen=%v", id, seen)
			}
		}
		for _, id := range []string{"mc-http", "se-bounty", "ws-scope"} {
			if seen[id] {
				t.Errorf("expected %s to remain unseen, got seen=%v", id, seen)
			}
		}
	})
}

func TestChangesVirtualCategoriesStatusTitleContentAndPrefixParsing(t *testing.T) {
	h, adminID := newIsoHandler(t)
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, []any{adminID}},
		// Status transitions:
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-status-flip','t1','r1','https://w1.one.example','status_change','status=200 title=Old','status=403 title=New','medium',200,403,'2026-07-01 00:00:01')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-status-same','t1','r1','https://w2.one.example','status_change','status=200 title=A','status=200 title=B','low',200,200,'2026-07-01 00:00:02')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http-both','t1','https://m1.one.example','http_change','status=403 title=Forbidden','status=200 title=OK','high',0,0,'2026-07-01 00:00:03')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http-status-only','t1','https://m2.one.example','http_change','status=200 title=App title=v1','status=500 title=App title=v1','high',200,500,'2026-07-01 00:00:04')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('wc-redirect','t1','r1','https://r1.one.example','redirect_change','https://a.example','https://b.example','medium',301,302,'2026-07-01 00:00:05')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-redirect','t1','https://r2.one.example','redirect_change','https://old.example','https://new.example','medium',0,0,'2026-07-01 00:00:06')`, nil},
		// Title changes:
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http-title-only','t1','https://t1.one.example','http_change','status=200 title=Alpha','status=200 title=Beta','low',200,200,'2026-07-01 00:00:07')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http-zero-status','t1','https://t2.one.example','http_change','status=0 title=','status=200 title=Home','low',0,200,'2026-07-01 00:00:08')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-http-extra-title','t1','https://t3.one.example','http_change','status=200 title=Foo title=One','status=200 title=Foo title=Two','low',200,200,'2026-07-01 00:00:09')`, nil},
		{`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('wc-page-raw','t1','r1','https://t4.one.example','page_change','Old Watch Title','New Watch Title','low','2026-07-01 00:00:10')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-page-empty-to-text','t1','https://t5.one.example','page_change','','Dashboard','low','2026-07-01 00:00:11')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-page-text-to-empty','t1','https://t6.one.example','page_change','Landing','','low','2026-07-01 00:00:12')`, nil},
		// Raw page_change whose title embeds "status=NNN " mid-string (must NOT spoof status parsing):
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-page-spoof','t1','https://spoof.one.example','page_change','API status=200 Live','API status=403 Maintenance','low',0,0,'2026-07-01 00:00:13')`, nil},
		// Body-only identical page_change rows (must NOT match category=title):
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-page-ident-raw','t1','https://id1.one.example','page_change','Same Title','Same Title','low',0,0,'2026-07-01 00:00:14')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
			VALUES ('mc-page-ident-fmt','t1','https://id2.one.example','page_change','status=200 title=Same','status=200 title=Same','low',200,200,'2026-07-01 00:00:15')`, nil},
		// Content, tech, and alert rows:
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-content','t1','https://c.one.example','content_change','hash=aaa','hash=bbb','low','2026-07-01 00:00:16')`, nil},
		{`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
			VALUES ('mc-tech','t1','https://tech.one.example','tech_change','nginx','cloudflare','low','2026-07-01 00:00:17')`, nil},
		{`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
			VALUES ('n-alert','t1','watch_failed','Round failed','status=200 title=A','high','2026-07-01 00:00:18')`, nil},
	} {
		if _, err := h.db.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed %s: %v", stmt.q, err)
		}
	}

	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	wantStatus := map[string]bool{
		"wc-status-flip":      true,
		"mc-http-both":        true,
		"mc-http-status-only": true,
		"wc-redirect":         true,
		"mc-redirect":         true,
	}
	wantTitle := map[string]bool{
		"mc-http-both":          true,
		"mc-http-title-only":    true,
		"mc-http-zero-status":   true,
		"mc-http-extra-title":   true,
		"wc-page-raw":           true,
		"mc-page-empty-to-text": true,
		"mc-page-text-to-empty": true,
		"mc-page-spoof":         true,
	}
	wantStatusOrTitle := map[string]bool{}
	for id := range wantStatus {
		wantStatusOrTitle[id] = true
	}
	for id := range wantTitle {
		wantStatusOrTitle[id] = true
	}

	cases := []struct {
		name string
		path string
		want map[string]bool
	}{
		{
			name: "category=status",
			path: "/api/changes?category=status",
			want: wantStatus,
		},
		{
			name: "category=all,status drops all",
			path: "/api/changes?category=all,status",
			want: wantStatus,
		},
		{
			name: "category=title",
			path: "/api/changes?category=title",
			want: wantTitle,
		},
		{
			name: "category=content",
			path: "/api/changes?category=content",
			want: map[string]bool{"mc-content": true},
		},
		{
			name: "category=status,title OR composition",
			path: "/api/changes?category=status,title",
			want: wantStatusOrTitle,
		},
		{
			name: "category=status,title with source=watch AND precedence",
			path: "/api/changes?category=status,title&source=watch",
			want: map[string]bool{
				"wc-status-flip": true,
				"wc-redirect":    true,
				"wc-page-raw":    true,
			},
		},
		{
			name: "category=tech,content mixes standard and virtual categories",
			path: "/api/changes?category=tech,content",
			want: map[string]bool{"mc-tech": true, "mc-content": true},
		},
		{
			name: "default_view=1 excludes raw page_change with embedded status=",
			path: "/api/changes?default_view=1",
			want: map[string]bool{
				"wc-status-flip":      true,
				"mc-http-both":        true,
				"mc-http-status-only": true,
			},
		},
		{
			name: "status_only=1 excludes raw page_change with embedded status=",
			path: "/api/changes?status_only=1",
			want: map[string]bool{
				"wc-status-flip":      true,
				"mc-http-both":        true,
				"mc-http-status-only": true,
				"wc-redirect":         true,
			},
		},
		{
			name: "status_code=403 excludes spoofed title",
			path: "/api/changes?status_code=403",
			want: map[string]bool{
				"wc-status-flip": true,
				"mc-http-both":   true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := idsOf(env.Data)
			if len(got) != len(tc.want) || env.Total != len(tc.want) {
				t.Fatalf("got ids=%v (total=%d), want %v", got, env.Total, tc.want)
			}
			for id := range tc.want {
				if !got[id] {
					t.Errorf("missing %q in %v", id, got)
				}
			}
		})
	}

	// Mark-all-seen with category=title marks only title rows and pairs cleanly with hide_seen=1.
	t.Run("seen-all with category=title marks only title rows", func(t *testing.T) {
		rec := postChanges(t, h, sid, "/api/changes/seen-all?category=title", map[string]any{}, h.handleMarkAllChangesSeen)
		if rec.Code != http.StatusOK {
			t.Fatalf("seen-all title status = %d, body = %s", rec.Code, rec.Body.String())
		}
		listRec := serveChanges(t, h, sid, "/api/changes", nil, h.handleListChanges)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(listRec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, row := range env.Data {
			if wantTitle[row.ID] && !row.Seen {
				t.Errorf("expected title row %s to be marked seen", row.ID)
			}
			if !wantTitle[row.ID] && row.Seen {
				t.Errorf("expected non-title row %s to remain unseen", row.ID)
			}
		}

		// category=status,title&hide_seen=1 must return only status rows not already marked seen by title.
		unreadRec := serveChanges(t, h, sid, "/api/changes?category=status,title&hide_seen=1", nil, h.handleListChanges)
		if unreadRec.Code != http.StatusOK {
			t.Fatalf("hide_seen status = %d, body = %s", unreadRec.Code, unreadRec.Body.String())
		}
		var unreadEnv changesEnvelope
		if err := json.Unmarshal(unreadRec.Body.Bytes(), &unreadEnv); err != nil {
			t.Fatalf("decode: %v", err)
		}
		gotUnread := idsOf(unreadEnv.Data)
		wantUnread := map[string]bool{
			"wc-status-flip":      true,
			"mc-http-status-only": true,
			"wc-redirect":         true,
			"mc-redirect":         true,
		}
		if len(gotUnread) != len(wantUnread) {
			t.Fatalf("category=status,title&hide_seen=1 ids=%v, want %v", gotUnread, wantUnread)
		}
		for id := range wantUnread {
			if !gotUnread[id] {
				t.Errorf("missing unread %q in %v", id, gotUnread)
			}
		}
	})

	// Mark-all-seen with category=status marks remaining status rows and leaves content/tech/alerts unseen.
	t.Run("seen-all with category=status marks only status rows", func(t *testing.T) {
		if _, err := h.db.Exec(`DELETE FROM change_seen`); err != nil {
			t.Fatal(err)
		}
		rec := postChanges(t, h, sid, "/api/changes/seen-all?category=status", map[string]any{}, h.handleMarkAllChangesSeen)
		if rec.Code != http.StatusOK {
			t.Fatalf("seen-all status = %d, body = %s", rec.Code, rec.Body.String())
		}
		listRec := serveChanges(t, h, sid, "/api/changes", nil, h.handleListChanges)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(listRec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, row := range env.Data {
			if wantStatus[row.ID] && !row.Seen {
				t.Errorf("expected status row %s to be marked seen", row.ID)
			}
			if !wantStatus[row.ID] && row.Seen {
				t.Errorf("expected non-status row %s to remain unseen", row.ID)
			}
		}
	})
}
