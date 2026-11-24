package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"github.com/recon-platform/internal/config"
)

func TestHTTPServicesIncludeObservedSeedOnly(t *testing.T) {
	h, _ := newIsoHandler(t)
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES ('hs-t','example.test')`)
	_, _ = h.db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,source,probe_tier) VALUES
		('hs-seen','hs-t','https://observed.example.test/',200,'seed','deep'),
		('hs-unseen','hs-t','https://untouched.example.test/',0,'seed',''),
		('hs-probe-zero','hs-t','https://zero.example.test/',0,'probe','deep')`)

	req := httptest.NewRequest("GET", "/api/targets/hs-t/http-services", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "hs-t"})
	rec := httptest.NewRecorder()
	h.handleListHTTPServices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data) != 1 || response.Data[0].ID != "hs-seen" {
		t.Fatalf("services=%+v, want only the observed seed", response.Data)
	}
}

func TestChangesSearchFindsHostBeyondPreviewLimit(t *testing.T) {
	h, _ := newIsoHandler(t)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES ('search-t','example.test')`)
	hosts := make([]string, 0, 501)
	for i := 0; i < 501; i++ {
		hosts = append(hosts, fmt.Sprintf("h%03d.example.test", i))
	}
	raw, err := json.Marshal(map[string]any{"hosts": hosts[:500], "all_hosts": hosts, "omitted": 1, "truncated": true, "total": 501})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.db.Exec(`INSERT INTO notifications(id,target_id,type,title,body,severity,metadata)
		VALUES ('n-search','search-t','new_host','New hosts','501 new subdomain(s)','info',?)`, string(raw))

	rec := serveChanges(t, h, sid, "/api/changes?q=h500.example.test", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "n-search" {
		t.Fatalf("data=%+v, want the hidden member's group", env.Data)
	}
}
