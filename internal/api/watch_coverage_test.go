package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/websocket"
)

func promoteRequest(h *Handler, targetID string, adminID int64, values ...string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"values": values})
	req := httptest.NewRequest("POST", "/api/targets/"+targetID+"/watch-scope/promote", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handlePromoteWatchScope(rec, req)
	return rec
}

func TestPromoteWatchScopeRejectsRevokedAsset(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES ('pv-t','example.test')`)
	_, _ = h.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status,asset_type,source)
		VALUES ('pv-a','pv-t','','app.example.test','suspended','subdomain','watch:scope')`)

	rec := promoteRequest(h, "pv-t", adminID, "app.example.test")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want conflict", rec.Code, rec.Body.String())
	}
	var assetType string
	_ = h.db.QueryRow(`SELECT asset_type FROM assets WHERE id='pv-a'`).Scan(&assetType)
	if assetType != "subdomain" {
		t.Fatalf("revoked asset was promoted to %q", assetType)
	}
}

func TestPromoteWatchScopeClearsStaleOutOfScopeMarker(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES ('pp-t','example.test')`)
	_, _ = h.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status,asset_type,source,metadata)
		VALUES ('pp-a','pp-t','','app.example.test','approved','subdomain','watch:scope','{"out_of_scope":1}')`)

	rec := promoteRequest(h, "pp-t", adminID, "app.example.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var typ, metadata string
	_ = h.db.QueryRow(`SELECT asset_type, COALESCE(metadata,'') FROM assets WHERE id='pp-a'`).Scan(&typ, &metadata)
	if typ != "url" {
		t.Fatalf("asset_type=%q, want url", typ)
	}
	var meta map[string]any
	_ = json.Unmarshal([]byte(metadata), &meta)
	if meta["out_of_scope"] != float64(0) || meta["promoted_to_deep"] != float64(1) {
		t.Fatalf("metadata=%s, want reconciled marker and promotion flag", metadata)
	}
}

func TestPromoteWatchScopeHonorsProgramEligibility(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES ('pg-t','example.test')`)
	_, _ = h.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES ('pg-p','test','pg-p','pg-p','Program')`)
	_, _ = h.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync) VALUES ('pg-t','pg-p',1)`)
	_, _ = h.db.Exec(`INSERT INTO bounty_program_assets
		(id,program_id,external_id,identifier,asset_type,in_scope,eligible_submission,active)
		VALUES ('pg-a','pg-p','pg-e','app.example.test','domain',1,1,1)`)
	_, _ = h.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status,asset_type,source)
		VALUES ('pg-w1','pg-t','','app.example.test','approved','subdomain','watch:scope'),
		       ('pg-w2','pg-t','','other.example.net','approved','subdomain','watch:scope')`)

	rec := promoteRequest(h, "pg-t", adminID, "other.example.net")
	if rec.Code != http.StatusConflict {
		t.Fatalf("ineligible host status=%d body=%s, want conflict", rec.Code, rec.Body.String())
	}
	rec = promoteRequest(h, "pg-t", adminID, "app.example.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("eligible host status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func coverageRequest(h *Handler, targetID string, adminID int64, body map[string]any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("PATCH", "/api/targets/"+targetID, bytes.NewReader(raw))
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleUpdateTarget(rec, req)
	return rec
}

func TestCoverageFlipDisablesMonitor(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,watch_only,monitor_enabled,watch_stagger_pending,watch_next_run)
		VALUES ('cf-t','example.test',1,1,1,'2026-01-01 00:00:00')`)
	_, _ = h.db.Exec(`INSERT INTO assets(id,target_id,value,asset_type,monitor_enabled)
		VALUES ('cf-a','cf-t','a.example.test','domain',1)`)

	rec := coverageRequest(h, "cf-t", adminID, map[string]any{"watch_only": false, "kind": "web"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var watchOnly, monitor, staggerPending, nextNull, assetMonitor int
	if err := h.db.QueryRow(`SELECT COALESCE(watch_only,-1), COALESCE(monitor_enabled,-1), COALESCE(watch_stagger_pending,-1), CASE WHEN watch_next_run IS NULL THEN 1 ELSE 0 END FROM targets WHERE id='cf-t'`).Scan(&watchOnly, &monitor, &staggerPending, &nextNull); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT COALESCE(monitor_enabled,-1) FROM assets WHERE id='cf-a'`).Scan(&assetMonitor); err != nil {
		t.Fatal(err)
	}
	if watchOnly != 0 || monitor != 0 || staggerPending != 0 || nextNull != 1 || assetMonitor != 0 {
		t.Fatalf("flip state watch=%d monitor=%d staggerPending=%d nextNull=%d assetMonitor=%d", watchOnly, monitor, staggerPending, nextNull, assetMonitor)
	}
}

func TestCoverageFlipToBreadthSetsStaggerPending(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,kind,watch_only,monitor_enabled,watch_stagger_pending)
		VALUES ('cb-t','example.test','web',0,1,0)`); err != nil {
		t.Fatal(err)
	}

	rec := coverageRequest(h, "cb-t", adminID, map[string]any{"watch_only": true, "kind": "web"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var watchOnly, staggerPending, nextNull int
	if err := h.db.QueryRow(`SELECT COALESCE(watch_only,-1), COALESCE(watch_stagger_pending,-1), CASE WHEN watch_next_run IS NULL THEN 1 ELSE 0 END FROM targets WHERE id='cb-t'`).
		Scan(&watchOnly, &staggerPending, &nextNull); err != nil {
		t.Fatal(err)
	}
	if watchOnly != 1 || staggerPending != 1 || nextNull != 0 {
		t.Fatalf("flip-to-breadth state watch=%d staggerPending=%d nextNull=%d, want 1/1/0", watchOnly, staggerPending, nextNull)
	}
}

func TestBulkCoverageSetsAndClearsStaggerPending(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,kind,watch_only,watch_stagger_pending)
		VALUES ('bc-1','one.test','web',0,0), ('bc-2','two.test','web',0,0)`); err != nil {
		t.Fatal(err)
	}

	doBulk := func(watchOnly bool) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"ids": []string{"bc-1", "bc-2"}, "watch_only": watchOnly})
		req := httptest.NewRequest(http.MethodPost, "/api/targets/bulk/coverage", bytes.NewReader(raw))
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
		rec := httptest.NewRecorder()
		h.handleBulkCoverage(rec, req)
		return rec
	}

	if rec := doBulk(true); rec.Code != http.StatusOK {
		t.Fatalf("bulk to breadth status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"bc-1", "bc-2"} {
		var watchOnly, staggerPending int
		if err := h.db.QueryRow(`SELECT COALESCE(watch_only,-1), COALESCE(watch_stagger_pending,-1) FROM targets WHERE id=?`, id).Scan(&watchOnly, &staggerPending); err != nil {
			t.Fatal(err)
		}
		if watchOnly != 1 || staggerPending != 1 {
			t.Fatalf("%s after bulk to breadth: watch=%d staggerPending=%d, want 1/1", id, watchOnly, staggerPending)
		}
	}

	if rec := doBulk(false); rec.Code != http.StatusOK {
		t.Fatalf("bulk to deep status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"bc-1", "bc-2"} {
		var watchOnly, staggerPending int
		if err := h.db.QueryRow(`SELECT COALESCE(watch_only,-1), COALESCE(watch_stagger_pending,-1) FROM targets WHERE id=?`, id).Scan(&watchOnly, &staggerPending); err != nil {
			t.Fatal(err)
		}
		if watchOnly != 0 || staggerPending != 0 {
			t.Fatalf("%s after bulk to deep: watch=%d staggerPending=%d, want 0/0", id, watchOnly, staggerPending)
		}
	}
}

func TestUnpauseRestartsWatchRound(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_fail_count)
		VALUES ('up-t','example.test',1,1,3)`)

	body, _ := json.Marshal(map[string]any{"watch_paused": false})
	req := httptest.NewRequest("PATCH", "/api/targets/up-t", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": "up-t"})
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleUpdateTarget(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var paused, fails, nextNull int
	if err := h.db.QueryRow(`SELECT COALESCE(watch_paused,-1), COALESCE(watch_fail_count,-1), CASE WHEN watch_next_run IS NULL THEN 1 ELSE 0 END FROM targets WHERE id='up-t'`).Scan(&paused, &fails, &nextNull); err != nil {
		t.Fatal(err)
	}
	if paused != 0 || fails != 0 || nextNull != 0 {
		t.Fatalf("unpause state paused=%d fails=%d nextNull=%d", paused, fails, nextNull)
	}
}

func TestAlreadyDeepNoOpPreservesMonitorEnabled(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,monitor_enabled,watch_paused,watch_next_run)
		VALUES ('ad-t','example.test',0,1,1,'2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO assets(id,target_id,value,asset_type,monitor_enabled)
		VALUES ('ad-a','ad-t','a.example.test','domain',1)`); err != nil {
		t.Fatal(err)
	}

	rec := coverageRequest(h, "ad-t", adminID, map[string]any{"watch_only": false, "kind": "web"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var watchOnly, monitor, paused, nextNull, assetMonitor int
	if err := h.db.QueryRow(`SELECT COALESCE(watch_only,-1), COALESCE(monitor_enabled,-1), COALESCE(watch_paused,-1), CASE WHEN watch_next_run IS NULL THEN 1 ELSE 0 END FROM targets WHERE id='ad-t'`).
		Scan(&watchOnly, &monitor, &paused, &nextNull); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT COALESCE(monitor_enabled,-1) FROM assets WHERE id='ad-a'`).Scan(&assetMonitor); err != nil {
		t.Fatal(err)
	}
	if watchOnly != 0 || monitor != 1 || paused != 0 || nextNull != 1 || assetMonitor != 1 {
		t.Fatalf("already-deep state watch=%d monitor=%d paused=%d nextNull=%d assetMonitor=%d, want 0/1/0/1/1",
			watchOnly, monitor, paused, nextNull, assetMonitor)
	}
}

func TestPromoteWatchScopeEmptyMetadataOnDeepMonitoredTarget(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,monitor_enabled) VALUES ('pm-t','example.test',0,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status,asset_type,source,monitor_enabled,metadata)
		VALUES ('pm-a','pm-t','','app.example.test','approved','subdomain','watch:scope',0,'')`); err != nil {
		t.Fatal(err)
	}

	rec := promoteRequest(h, "pm-t", adminID, "app.example.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var typ, metadata string
	var monitor int
	if err := h.db.QueryRow(`SELECT asset_type, COALESCE(monitor_enabled,-1), COALESCE(metadata,'') FROM assets WHERE id='pm-a'`).
		Scan(&typ, &monitor, &metadata); err != nil {
		t.Fatal(err)
	}
	if typ != "url" || monitor != 1 {
		t.Fatalf("promoted asset_type=%q monitor_enabled=%d, want url and 1", typ, monitor)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(metadata), &meta); err != nil {
		t.Fatalf("metadata %q invalid JSON: %v", metadata, err)
	}
	if meta["promoted_to_deep"] != float64(1) || meta["out_of_scope"] != float64(0) {
		t.Fatalf("metadata=%s, want promoted_to_deep=1 and out_of_scope=0", metadata)
	}
}

func addAssetRequest(h *Handler, targetID string, adminID int64, body map[string]any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+targetID+"/assets", bytes.NewReader(raw))
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleAddAsset(rec, req)
	return rec
}

func TestHandleAddAssetWatchOnlyWildcardAndScheduleNudge(t *testing.T) {
	t.Run("unpaused watch target normalizes scheme wildcard and pulls future schedule forward", func(t *testing.T) {
		h, adminID := newIsoHandler(t)
		h.hub = websocket.NewHub()
		if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_next_run)
			VALUES ('wa-t1','example.com',1,0,datetime('now', '+6 hours'))`); err != nil {
			t.Fatal(err)
		}
		var beforeNext string
		if err := h.db.QueryRow(`SELECT watch_next_run FROM targets WHERE id='wa-t1'`).Scan(&beforeNext); err != nil {
			t.Fatal(err)
		}

		rec := addAssetRequest(h, "wa-t1", adminID, map[string]any{"value": "https://*.example.com/"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Success bool         `json:"success"`
			Data    models.Asset `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Data.AssetType != "wildcard" || env.Data.MonitorEnabled {
			t.Fatalf("response asset_type=%q monitor_enabled=%v, want wildcard / false", env.Data.AssetType, env.Data.MonitorEnabled)
		}

		var assetType string
		var monitor int
		if err := h.db.QueryRow(`SELECT asset_type, monitor_enabled FROM assets WHERE target_id='wa-t1' AND value='https://*.example.com/'`).Scan(&assetType, &monitor); err != nil {
			t.Fatal(err)
		}
		if assetType != "wildcard" || monitor != 0 {
			t.Fatalf("db asset_type=%q monitor_enabled=%d, want wildcard / 0", assetType, monitor)
		}

		var nudged int
		var afterNext string
		if err := h.db.QueryRow(`SELECT COALESCE(watch_next_run,''), CASE WHEN watch_next_run <= datetime('now', '+5 seconds') AND watch_next_run < ? THEN 1 ELSE 0 END FROM targets WHERE id='wa-t1'`, beforeNext).Scan(&afterNext, &nudged); err != nil {
			t.Fatal(err)
		}
		if nudged != 1 {
			t.Fatalf("future watch_next_run not pulled forward: before=%q after=%q", beforeNext, afterNext)
		}
	})

	t.Run("paused watch target keeps pause and future schedule", func(t *testing.T) {
		h, adminID := newIsoHandler(t)
		h.hub = websocket.NewHub()
		if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_next_run)
			VALUES ('wa-t2','example.com',1,1,'2099-01-01 00:00:00')`); err != nil {
			t.Fatal(err)
		}
		rec := addAssetRequest(h, "wa-t2", adminID, map[string]any{"value": "https://*.paused.example.com/"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var paused int
		var nextRun string
		if err := h.db.QueryRow(`SELECT COALESCE(watch_paused,-1), COALESCE(watch_next_run,'') FROM targets WHERE id='wa-t2'`).Scan(&paused, &nextRun); err != nil {
			t.Fatal(err)
		}
		if paused != 1 || nextRun != "2099-01-01 00:00:00" {
			t.Fatalf("paused target mutated: paused=%d watch_next_run=%q", paused, nextRun)
		}
	})

	t.Run("overdue watch target schedule is not demoted", func(t *testing.T) {
		h, adminID := newIsoHandler(t)
		h.hub = websocket.NewHub()
		if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_next_run)
			VALUES ('wa-t3','example.com',1,0,'2020-01-01 00:00:00')`); err != nil {
			t.Fatal(err)
		}
		rec := addAssetRequest(h, "wa-t3", adminID, map[string]any{"value": "https://*.overdue.example.com/"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var nextRun string
		if err := h.db.QueryRow(`SELECT COALESCE(watch_next_run,'') FROM targets WHERE id='wa-t3'`).Scan(&nextRun); err != nil {
			t.Fatal(err)
		}
		if nextRun != "2020-01-01 00:00:00" {
			t.Fatalf("overdue watch_next_run demoted to %q", nextRun)
		}
	})

	t.Run("null watch schedule is not woken and missing target returns 404", func(t *testing.T) {
		h, adminID := newIsoHandler(t)
		h.hub = websocket.NewHub()
		if _, err := h.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_next_run)
			VALUES ('wa-t4','example.com',1,0,NULL)`); err != nil {
			t.Fatal(err)
		}
		rec := addAssetRequest(h, "wa-t4", adminID, map[string]any{"value": "https://*.nullsched.example.com/"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var isNull int
		if err := h.db.QueryRow(`SELECT CASE WHEN watch_next_run IS NULL THEN 1 ELSE 0 END FROM targets WHERE id='wa-t4'`).Scan(&isNull); err != nil {
			t.Fatal(err)
		}
		if isNull != 1 {
			t.Fatalf("null watch_next_run was unexpectedly populated")
		}

		missing := addAssetRequest(h, "does-not-exist", adminID, map[string]any{"value": "https://*.missing.example.com/"})
		if missing.Code != http.StatusNotFound {
			t.Fatalf("missing target status=%d, want 404", missing.Code)
		}
	})
}
