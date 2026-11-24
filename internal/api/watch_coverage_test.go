package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

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
