package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/models"
)

func TestTargetListSubdomainsHTTPServicesParametersPagingAndFilters(t *testing.T) {
	h, adminID := newIsoHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	// Insert 205 subdomains to verify limit=500 isn't reverted to 100 and offset works.
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("sub-%03d", i)
		name := fmt.Sprintf("h%03d.example.test", i)
		if i == 0 {
			name = "alpha_one.example.test"
		} else if i == 1 {
			name = "alphaXone.example.test"
		} else if i == 2 {
			name = "pct%host.example.test"
		}
		created := "2020-01-01 00:00:00"
		if i == 204 {
			created = "2099-01-01 00:00:00"
		}
		alive := 1
		status := 200
		if i%2 == 1 {
			alive = 0
			status = 404
		}
		if _, err := h.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, ip, is_alive, status_code, page_title, created_at)
			VALUES (?, 't1', ?, '1.2.3.4', ?, ?, 'Home', ?)`, id, name, alive, status, created); err != nil {
			t.Fatal(err)
		}
	}
	// Also test new_only with datetime('now') row.
	if _, err := h.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, ip, is_alive, status_code, page_title, created_at)
		VALUES ('sub-recent', 't1', 'recent.example.test', '5.6.7.8', 1, 503, 'Down', datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	get := func(path string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = mux.SetURLVars(req, map[string]string{"id": "t1"})
		req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
		rec := httptest.NewRecorder()
		h.requireAuth(handler)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		return rec
	}

	// 1. Subdomains: limit=500 returns all 206 (not clamped down to 100!).
	var subEnv struct {
		Data  []models.Subdomain `json:"data"`
		Total int                `json:"total"`
		Limit int                `json:"limit"`
	}
	rec := get("/api/targets/t1/subdomains?limit=500", h.handleListSubdomains)
	if err := json.Unmarshal(rec.Body.Bytes(), &subEnv); err != nil {
		t.Fatal(err)
	}
	if subEnv.Total != 206 || len(subEnv.Data) != 206 || subEnv.Limit != 500 {
		t.Fatalf("limit=500 got total=%d len=%d limit=%d", subEnv.Total, len(subEnv.Data), subEnv.Limit)
	}

	// 2. Subdomains: offset=200&limit=10 skips first 200 rows.
	subEnv.Data = nil
	rec = get("/api/targets/t1/subdomains?offset=200&limit=10", h.handleListSubdomains)
	if err := json.Unmarshal(rec.Body.Bytes(), &subEnv); err != nil {
		t.Fatal(err)
	}
	if len(subEnv.Data) != 6 || subEnv.Total != 206 {
		t.Fatalf("offset=200 got len=%d total=%d, want 6/206", len(subEnv.Data), subEnv.Total)
	}

	// 3. Subdomains: ESCAPE '\' treats '_' and '%' literally.
	subEnv.Data = nil
	rec = get("/api/targets/t1/subdomains?q=alpha_one", h.handleListSubdomains)
	if err := json.Unmarshal(rec.Body.Bytes(), &subEnv); err != nil {
		t.Fatal(err)
	}
	if len(subEnv.Data) != 1 || subEnv.Data[0].Subdomain != "alpha_one.example.test" {
		t.Fatalf("underscore search got %+v, want only alpha_one.example.test", subEnv.Data)
	}
	subEnv.Data = nil
	rec = get("/api/targets/t1/subdomains?search=pct%25host", h.handleListSubdomains)
	if err := json.Unmarshal(rec.Body.Bytes(), &subEnv); err != nil {
		t.Fatal(err)
	}
	if len(subEnv.Data) != 1 || subEnv.Data[0].Subdomain != "pct%host.example.test" {
		t.Fatalf("percent search got %+v, want only pct%%host.example.test", subEnv.Data)
	}

	// 4. Subdomains: new_only=1 & sort=status&dir=desc.
	subEnv.Data = nil
	rec = get("/api/targets/t1/subdomains?new_only=1&sort=status&dir=desc", h.handleListSubdomains)
	if err := json.Unmarshal(rec.Body.Bytes(), &subEnv); err != nil {
		t.Fatal(err)
	}
	if len(subEnv.Data) != 2 || subEnv.Data[0].Subdomain != "recent.example.test" {
		t.Fatalf("new_only+sort=status desc got %+v", subEnv.Data)
	}

	// 5. HTTP services: status_class, new_only, ESCAPE '\', sort=size&dir=desc, offset.
	if _, err := h.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code, title, content_length, source, created_at) VALUES
		('hs-1','t1','https://a_b.example.test',200,'Alpha_Title',100,'probe',datetime('now')),
		('hs-2','t1','https://axb.example.test',404,'Other',500,'probe','2020-01-01 00:00:00'),
		('hs-3','t1','https://c.example.test',502,'Gateway',250,'probe',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	var httpEnv struct {
		Data  []models.HTTPService `json:"data"`
		Total int                  `json:"total"`
	}
	rec = get("/api/targets/t1/http-services?q=a_b", h.handleListHTTPServices)
	if err := json.Unmarshal(rec.Body.Bytes(), &httpEnv); err != nil {
		t.Fatal(err)
	}
	if len(httpEnv.Data) != 1 || httpEnv.Data[0].ID != "hs-1" {
		t.Fatalf("http-services underscore search got %+v, want hs-1", httpEnv.Data)
	}

	httpEnv.Data = nil
	rec = get("/api/targets/t1/http-services?status_class=5", h.handleListHTTPServices)
	if err := json.Unmarshal(rec.Body.Bytes(), &httpEnv); err != nil {
		t.Fatal(err)
	}
	if len(httpEnv.Data) != 1 || httpEnv.Data[0].ID != "hs-3" {
		t.Fatalf("status_class=5 got %+v, want hs-3", httpEnv.Data)
	}

	httpEnv.Data = nil
	rec = get("/api/targets/t1/http-services?new_only=1&sort=size&dir=desc&offset=1&limit=500", h.handleListHTTPServices)
	if err := json.Unmarshal(rec.Body.Bytes(), &httpEnv); err != nil {
		t.Fatal(err)
	}
	if httpEnv.Total != 2 || len(httpEnv.Data) != 1 || httpEnv.Data[0].ID != "hs-1" {
		t.Fatalf("http-services new_only+sort=size desc+offset=1 got total=%d data=%+v", httpEnv.Total, httpEnv.Data)
	}

	// 6. Parameters: limit, offset, reflected, search/q with ESCAPE '\'.
	if _, err := h.db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, source, is_reflected) VALUES
		('p-1','t1','https://a.example.test/search','user_id','1','crawler',1),
		('p-2','t1','https://a.example.test/search','userXid','2','crawler',0),
		('p-3','t1','https://b.example.test/api_v1','token','x','js',1)`); err != nil {
		t.Fatal(err)
	}
	var paramEnv struct {
		Data  []models.Parameter `json:"data"`
		Total int                `json:"total"`
		Limit int                `json:"limit"`
	}
	rec = get("/api/targets/t1/parameters?limit=500&offset=1", h.handleListParameters)
	if err := json.Unmarshal(rec.Body.Bytes(), &paramEnv); err != nil {
		t.Fatal(err)
	}
	if paramEnv.Total != 3 || len(paramEnv.Data) != 2 || paramEnv.Limit != 500 {
		t.Fatalf("parameters limit=500&offset=1 got total=%d len=%d limit=%d", paramEnv.Total, len(paramEnv.Data), paramEnv.Limit)
	}

	paramEnv.Data = nil
	rec = get("/api/targets/t1/parameters?q=user_id&reflected=true", h.handleListParameters)
	if err := json.Unmarshal(rec.Body.Bytes(), &paramEnv); err != nil {
		t.Fatal(err)
	}
	if len(paramEnv.Data) != 1 || paramEnv.Data[0].ID != "p-1" {
		t.Fatalf("parameters q=user_id&reflected=true got %+v, want p-1", paramEnv.Data)
	}

	paramEnv.Data = nil
	rec = get("/api/targets/t1/parameters?search=api_v1", h.handleListParameters)
	if err := json.Unmarshal(rec.Body.Bytes(), &paramEnv); err != nil {
		t.Fatal(err)
	}
	if len(paramEnv.Data) != 1 || paramEnv.Data[0].ID != "p-3" {
		t.Fatalf("parameters URL search api_v1 got %+v, want p-3", paramEnv.Data)
	}
}

func TestTargetProgramLogoSelectionAndValidation(t *testing.T) {
	h, adminID := newIsoHandler(t)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES
		('t-none','none.example',?),
		('t-one','one.example',?),
		('t-two','two.example',?)`, adminID, adminID, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO bounty_programs (id, provider, external_id, handle, name, logo_url) VALUES
		('bp-valid1','bugcrowd','e1','one','One','https://cdn.example.com/one.png'),
		('bp-rel','bugcrowd','e2','rel','Rel','/assets/relative.png'),
		('bp-js','bugcrowd','e3','js','JS','javascript:alert(1)'),
		('bp-emptyhost','bugcrowd','e4','empty','Empty','https://'),
		('bp-valid2','yeswehack','e5','two','Two','https://cdn.example.com/two.png')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO project_programs (target_id, program_id, created_at) VALUES
		('t-one','bp-valid1','2026-01-01 00:00:00'),
		('t-two','bp-rel','2026-01-01 00:00:00'),
		('t-two','bp-js','2026-01-01 00:00:01'),
		('t-two','bp-emptyhost','2026-01-01 00:00:02'),
		('t-two','bp-valid2','2026-01-01 00:00:03')`); err != nil {
		t.Fatal(err)
	}

	// List targets
	req := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.requireAuth(h.handleListTargets)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list targets status=%d body=%s", rec.Code, rec.Body.String())
	}
	var listEnv struct {
		Data []models.Target `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listEnv); err != nil {
		t.Fatal(err)
	}
	if len(listEnv.Data) != 3 {
		t.Fatalf("list len=%d, want 3", len(listEnv.Data))
	}
	byID := map[string]models.Target{}
	for _, tgt := range listEnv.Data {
		byID[tgt.ID] = tgt
	}
	if byID["t-none"].ProgramLogoURL != "" {
		t.Errorf("t-none ProgramLogoURL = %q, want empty", byID["t-none"].ProgramLogoURL)
	}
	if byID["t-one"].ProgramLogoURL != "https://cdn.example.com/one.png" {
		t.Errorf("t-one ProgramLogoURL = %q, want https://cdn.example.com/one.png", byID["t-one"].ProgramLogoURL)
	}
	if byID["t-two"].ProgramLogoURL != "https://cdn.example.com/two.png" {
		t.Errorf("t-two ProgramLogoURL = %q, want https://cdn.example.com/two.png", byID["t-two"].ProgramLogoURL)
	}

	// Single get target for t-two
	greq := httptest.NewRequest(http.MethodGet, "/api/targets/t-two", nil)
	greq = mux.SetURLVars(greq, map[string]string{"id": "t-two"})
	greq.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	grec := httptest.NewRecorder()
	h.requireAuth(h.handleGetTarget)(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("get target status=%d body=%s", grec.Code, grec.Body.String())
	}
	var getEnv struct {
		Data models.Target `json:"data"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &getEnv); err != nil {
		t.Fatal(err)
	}
	if getEnv.Data.ProgramLogoURL != "https://cdn.example.com/two.png" {
		t.Errorf("get target t-two ProgramLogoURL = %q, want https://cdn.example.com/two.png", getEnv.Data.ProgramLogoURL)
	}
}

func TestTargetListPaginationOverflowAndOffsetPage(t *testing.T) {
	cases := []struct {
		name                            string
		query                           string
		wantPage, wantLimit, wantOffset int
	}{
		{"normal page", "?page=3&limit=50", 3, 50, 100},
		{"extreme page does not wrap", fmt.Sprintf("?page=%d&limit=500", math.MaxInt), math.MaxInt, 500, math.MaxInt},
		{"negative offset ignored", "?offset=-5&page=2&limit=200", 2, 200, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/targets/t1/subdomains"+tc.query, nil)
			page, limit, offset := targetListPagination(req, 200, 500)
			if page != tc.wantPage || limit != tc.wantLimit || offset != tc.wantOffset {
				t.Fatalf("got page=%d limit=%d offset=%d, want %d/%d/%d",
					page, limit, offset, tc.wantPage, tc.wantLimit, tc.wantOffset)
			}
		})
	}
}
