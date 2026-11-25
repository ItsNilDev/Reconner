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
