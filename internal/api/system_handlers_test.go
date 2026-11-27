package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mattn/go-sqlite3"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scheduler"
)

// TestHandleMergeCorpusAcceptsBodyLargerThanOldTwoMebibyteCap proves an
// operator wordlist well above the OLD 2 MiB request-body ceiling (which
// http.MaxBytesReader would have rejected outright, surfacing as a decode
// error / 400) is now accepted end to end through the real HTTP handler. A
// full 500 MiB body would make this test needlessly slow; a body several
// times the OLD cap is enough to prove that specific limit is gone.
func TestHandleMergeCorpusAcceptsBodyLargerThanOldTwoMebibyteCap(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.WordlistsDir = t.TempDir()

	const oldCapBytes = 2 << 20
	var sb strings.Builder
	for i := 0; sb.Len() < oldCapBytes*3; i++ {
		fmt.Fprintf(&sb, "word%d\n", i)
	}
	payload, err := json.Marshal(map[string]string{"text": sb.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= oldCapBytes {
		t.Fatalf("test fixture (%d bytes) must exceed the old %d-byte cap", len(payload), oldCapBytes)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/corpora/subdomain", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"category": "subdomain"})
	rec := httptest.NewRecorder()
	h.handleMergeCorpus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a %d-byte body (well above the old 2 MiB cap) must be accepted: status=%d body=%s",
			len(payload), rec.Code, rec.Body.String())
	}
}

// patchScanCfg POSTs a scan-config PATCH directly through the real handler and
// returns the decoded GET payload. The handler persists to RECON_CONFIG, so the
// test points it at a temp file and gives the handler a real Config + scheduler.
func patchScanCfg(t *testing.T, body map[string]int) scanConfigPayload {
	t.Helper()
	t.Setenv("RECON_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newIsoHandler(t)
	h.cfg = cfg
	h.sched = scheduler.New(h.db, nil, cfg, h.logger)

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	preq := httptest.NewRequest(http.MethodPost, "/api/system/scan-config", bytes.NewReader(raw))
	prec := httptest.NewRecorder()
	h.handleUpdateScanConfig(prec, preq)
	if prec.Code != http.StatusOK {
		t.Fatalf("PATCH failed: status=%d body=%s", prec.Code, prec.Body.String())
	}

	greq := httptest.NewRequest(http.MethodGet, "/api/system/scan-config", nil)
	grec := httptest.NewRecorder()
	h.handleGetScanConfig(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET failed: status=%d body=%s", grec.Code, grec.Body.String())
	}
	var env struct {
		Data scanConfigPayload `json:"data"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func TestScanConfigConcurrencyAuthoritative(t *testing.T) {
	want := map[string]int{
		"max_concurrent_scans":       runtime.NumCPU() + 3,
		"max_concurrent_deep_scans":  8,
		"max_concurrent_watch_scans": 16,
	}
	got := patchScanCfg(t, want)
	if got.MaxConcurrentScans != want["max_concurrent_scans"] ||
		got.MaxConcurrentDeepScans != want["max_concurrent_deep_scans"] ||
		got.MaxConcurrentWatchScans != want["max_concurrent_watch_scans"] {
		t.Fatalf("saved values not returned exactly: got total/deep/watch=%d/%d/%d want %d/%d/%d",
			got.MaxConcurrentScans, got.MaxConcurrentDeepScans, got.MaxConcurrentWatchScans,
			want["max_concurrent_scans"], want["max_concurrent_deep_scans"], want["max_concurrent_watch_scans"])
	}
	// The visible hardware envelope must be populated, not hidden.
	if got.HealthyEnvelopeTotal <= 0 || got.HealthyEnvelopeDeep <= 0 || got.HealthyEnvelopeWatch <= 0 {
		t.Fatalf("envelope hints missing: total/deep/watch=%d/%d/%d",
			got.HealthyEnvelopeTotal, got.HealthyEnvelopeDeep, got.HealthyEnvelopeWatch)
	}
}

func TestScanConfigConcurrencyClamps(t *testing.T) {
	cases := []struct {
		name                           string
		body                           map[string]int
		wantTotal, wantDeep, wantWatch int
	}{
		{"watch zero accepted", map[string]int{"max_concurrent_watch_scans": 0}, 2, 1, 0},
		{"total below floor", map[string]int{"max_concurrent_scans": 0}, 1, 1, 1},
		{"total above ceiling", map[string]int{"max_concurrent_scans": 100}, 32, 1, 1},
		{"deep above ceiling", map[string]int{"max_concurrent_deep_scans": 100}, 2, 8, 1},
		{"watch above ceiling", map[string]int{"max_concurrent_watch_scans": 100}, 2, 1, 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := patchScanCfg(t, tc.body)
			if got.MaxConcurrentScans != tc.wantTotal || got.MaxConcurrentDeepScans != tc.wantDeep ||
				got.MaxConcurrentWatchScans != tc.wantWatch {
				t.Fatalf("got total/deep/watch=%d/%d/%d want %d/%d/%d",
					got.MaxConcurrentScans, got.MaxConcurrentDeepScans, got.MaxConcurrentWatchScans,
					tc.wantTotal, tc.wantDeep, tc.wantWatch)
			}
		})
	}
}

func TestScanConfigConcurrencyPersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("RECON_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newIsoHandler(t)
	h.cfg = cfg
	h.sched = scheduler.New(h.db, nil, cfg, h.logger)

	raw, err := json.Marshal(map[string]int{
		"max_concurrent_scans":       runtime.NumCPU() + 3,
		"max_concurrent_deep_scans":  8,
		"max_concurrent_watch_scans": 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/system/scan-config", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.handleUpdateScanConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	reloaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Limits.MaxConcurrentScans != runtime.NumCPU()+3 ||
		reloaded.Limits.MaxConcurrentDeepScans != 8 ||
		reloaded.Limits.MaxConcurrentWatchScans != 16 {
		t.Fatalf("values did not survive Save/Load: total/deep/watch=%d/%d/%d",
			reloaded.Limits.MaxConcurrentScans, reloaded.Limits.MaxConcurrentDeepScans,
			reloaded.Limits.MaxConcurrentWatchScans)
	}
}

func TestScanConfigValidationDoesNotMutateInMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("RECON_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DNSResolvers = []string{"1.1.1.1"}
	cfg.SetConcurrencyLimits(4, 2, 2)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	h, _ := newIsoHandler(t)
	h.cfg = cfg
	h.sched = scheduler.New(h.db, nil, cfg, h.logger)

	raw, err := json.Marshal(map[string]any{
		"max_concurrent_scans":      12,
		"dns_resolvers":             []string{"9.9.9.9"},
		"watch_enumeration_sources": []string{"bogus"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/system/scan-config", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.handleUpdateScanConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bogus watch_enumeration_sources, got %d body=%s", rec.Code, rec.Body.String())
	}

	gotG, gotD, gotW := h.cfg.ConcurrencyLimits()
	if gotG != 4 || gotD != 2 || gotW != 2 {
		t.Fatalf("invalid request mutated concurrency limits in memory: got %d/%d/%d want 4/2/2", gotG, gotD, gotW)
	}
	if len(h.cfg.DNSResolvers) != 1 || h.cfg.DNSResolvers[0] != "1.1.1.1" {
		t.Fatalf("invalid request mutated dns_resolvers in memory: got %v want [1.1.1.1]", h.cfg.DNSResolvers)
	}
}

func TestScanConfigSaveFailureRollsBackInMemory(t *testing.T) {
	h, _ := newIsoHandler(t)
	// Config with no backing path forces SaveLocked() to fail.
	h.cfg = &config.Config{
		DNSResolvers: []string{"1.1.1.1"},
	}
	h.cfg.SetConcurrencyLimits(3, 1, 1)

	raw, err := json.Marshal(map[string]any{
		"max_concurrent_scans": 10,
		"dns_resolvers":        []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/system/scan-config", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.handleUpdateScanConfig(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when Save fails, got %d body=%s", rec.Code, rec.Body.String())
	}

	gotG, gotD, gotW := h.cfg.ConcurrencyLimits()
	if gotG != 3 || gotD != 1 || gotW != 1 {
		t.Fatalf("failed Save did not roll back concurrency limits: got %d/%d/%d want 3/1/1", gotG, gotD, gotW)
	}
	if len(h.cfg.DNSResolvers) != 1 || h.cfg.DNSResolvers[0] != "1.1.1.1" {
		t.Fatalf("failed Save did not roll back dns_resolvers: got %v want [1.1.1.1]", h.cfg.DNSResolvers)
	}
}

func TestScanConfigSaveFailureNeverExposesUncommittedLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("RECON_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DNSResolvers = []string{"1.1.1.1"}
	cfg.SetConcurrencyLimits(3, 1, 1)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	// Replace the config file with a non-empty directory so SaveCandidateLocked
	// executes apply/marshal/rollback and then fails during os.Rename.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	h, _ := newIsoHandler(t)
	h.cfg = cfg
	h.sched = scheduler.New(h.db, nil, cfg, h.logger)

	raw, err := json.Marshal(map[string]any{
		"max_concurrent_scans":       10,
		"max_concurrent_deep_scans":  4,
		"max_concurrent_watch_scans": 5,
		"dns_resolvers":              []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var sawUncommitted atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			g, d, w := h.cfg.ConcurrencyLimits()
			if g != 3 || d != 1 || w != 1 {
				sawUncommitted.Store(true)
				return
			}
		}
	}()

	for range 20 {
		req := httptest.NewRequest(http.MethodPost, "/api/system/scan-config", bytes.NewReader(raw))
		rec := httptest.NewRecorder()
		h.handleUpdateScanConfig(rec, req)
		if rec.Code != http.StatusInternalServerError {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("expected 500 when rename fails, got %d body=%s", rec.Code, rec.Body.String())
		}
	}
	stop.Store(true)
	wg.Wait()

	if sawUncommitted.Load() {
		t.Fatalf("concurrent ConcurrencyLimits() reader observed uncommitted values during failed save")
	}
	if gotG, gotD, gotW := h.cfg.ConcurrencyLimits(); gotG != 3 || gotD != 1 || gotW != 1 {
		t.Fatalf("concurrency limits after failed save = %d/%d/%d, want 3/1/1", gotG, gotD, gotW)
	}
	if len(h.cfg.DNSResolvers) != 1 || h.cfg.DNSResolvers[0] != "1.1.1.1" {
		t.Fatalf("dns_resolvers after failed save = %v, want [1.1.1.1]", h.cfg.DNSResolvers)
	}
}

func TestIsSQLiteBusy(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "ErrBusy", err: sqlite3.Error{Code: sqlite3.ErrBusy}, want: true},
		{name: "ErrLocked", err: sqlite3.Error{Code: sqlite3.ErrLocked}, want: true},
		{name: "wrapped ErrBusy", err: fmt.Errorf("wrap: %w", sqlite3.Error{Code: sqlite3.ErrBusy}), want: true},
		{name: "ErrConstraint", err: sqlite3.Error{Code: sqlite3.ErrConstraint}, want: false},
		{name: "database is locked msg", err: errors.New("database is locked"), want: true},
		{name: "database table is locked msg", err: errors.New("database table is locked"), want: true},
		{name: "busy msg", err: errors.New("SQLITE_BUSY"), want: true},
		{name: "other error", err: errors.New("connection refused"), want: false},
	}
	for _, tc := range cases {
		if got := isSQLiteBusy(tc.err); got != tc.want {
			t.Errorf("%s: isSQLiteBusy(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestDashboardBadgesOwnerIsolationAndEmptyDB(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}

	// Route through the real router so registration, the GET method
	// restriction, and requireAuth are all exercised, not just the handler.
	router := h.Router()
	readBadges := func(sid string) map[string]int {
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/badges", nil)
		req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("badges status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data map[string]int `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env.Data
	}

	anonRec := httptest.NewRecorder()
	router.ServeHTTP(anonRec, httptest.NewRequest(http.MethodGet, "/api/dashboard/badges", nil))
	if anonRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated badges status=%d, want 401; body=%s", anonRec.Code, anonRec.Body.String())
	}
	postReq := httptest.NewRequest(http.MethodPost, "/api/dashboard/badges", nil)
	postReq.AddCookie(&http.Cookie{Name: "recon_session", Value: adminSID})
	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, postReq)
	// mux has no POST route registered here, so it answers 404 (or 405 on
	// routers that register a method-agnostic path). Either way the handler
	// must not serve the GET-only endpoint.
	if postRec.Code != http.StatusNotFound && postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST badges status=%d, want 404/405; body=%s", postRec.Code, postRec.Body.String())
	}

	// Empty DB check.
	if got := readBadges(adminSID); got["targets"] != 0 || got["running_tasks"] != 0 {
		t.Fatalf("empty DB admin badges = %+v, want 0/0", got)
	}
	if got := readBadges(bobSID); got["targets"] != 0 || got["running_tasks"] != 0 {
		t.Fatalf("empty DB member badges = %+v, want 0/0", got)
	}

	if _, err := h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-a','a.example',?), ('t-b1','b1.example',?), ('t-b2','b2.example',?)`, adminID, bob.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO tasks (id, target_id, type, status) VALUES
		('tk-a1','t-a','deep_scan','running'),
		('tk-a2','t-a','deep_scan','finished'),
		('tk-b1','t-b1','watch_scan','running'),
		('tk-b2','t-b2','deep_scan','running'),
		('tk-b3','t-b2','deep_scan','failed')`); err != nil {
		t.Fatal(err)
	}

	adminBadges := readBadges(adminSID)
	if adminBadges["targets"] != 3 || adminBadges["running_tasks"] != 3 {
		t.Fatalf("admin badges = %+v, want targets=3 running_tasks=3", adminBadges)
	}
	bobBadges := readBadges(bobSID)
	if bobBadges["targets"] != 2 || bobBadges["running_tasks"] != 2 {
		t.Fatalf("bob badges = %+v, want targets=2 running_tasks=2", bobBadges)
	}
}

func TestDashboardStatsConsolidatedEmptyAndPopulated(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	zeroUser, err := h.auth.CreateUser("zero", "zeropassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	_ = zeroUser
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	zeroSID, err := h.auth.Login("zero", "zeropassword")
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}

	readStats := func(sid string) models.DashboardStats {
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/stats", nil)
		req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
		rec := httptest.NewRecorder()
		h.requireAuth(h.handleDashboardStats)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data models.DashboardStats `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env.Data
	}

	// Empty DB & zero-target member must succeed without NULL scan errors.
	if got := readStats(adminSID); got != (models.DashboardStats{}) {
		t.Fatalf("empty DB stats = %+v, want zero struct", got)
	}
	if got := readStats(zeroSID); got != (models.DashboardStats{}) {
		t.Fatalf("zero-target member stats = %+v, want zero struct", got)
	}

	if _, err := h.db.Exec(`INSERT INTO targets (id, domain, owner_id, watch_only) VALUES
		('t-deep','deep.example',?,0),
		('t-watch','watch.example',?,1),
		('t-bob','bob.example',?,1)`, adminID, adminID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, is_alive) VALUES
		('s1','t-deep','a.deep.example',1),
		('s2','t-deep','b.deep.example',0),
		('s3','t-watch','a.watch.example',1),
		('s4','t-bob','a.bob.example',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES
		('h1','t-deep','https://a.deep.example',200),
		('h2','t-watch','https://a.watch.example',200),
		('h3','t-bob','https://a.bob.example',200)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, is_reflected) VALUES
		('p1','t-deep','https://a.deep.example','q',1),
		('p2','t-deep','https://a.deep.example','page',0),
		('p3','t-bob','https://a.bob.example','id',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO tasks (id, target_id, type, status) VALUES
		('k1','t-deep','deep_scan','running'),
		('k2','t-deep','deep_scan','finished'),
		('k3','t-watch','watch_scan','running'),
		('k4','t-watch','watch_scan','failed'),
		('k5','t-bob','watch_scan','pending')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, status) VALUES
		('vf1','t-deep','xss','high','https://a.deep.example/1','finding'),
		('vf2','t-deep','xss','low','https://a.deep.example/2','candidate'),
		('vf3','t-bob','sqli','high','https://a.bob.example/1','finding')`); err != nil {
		t.Fatal(err)
	}
	// Populate every singleQueries table across admin-owned and member-owned
	// targets, including rows the surfaced/confirmed filters must exclude.
	if _, err := h.db.Exec(`INSERT INTO js_files (id,target_id,url) VALUES
		('j1','t-deep','https://a.deep.example/1.js'),
		('j2','t-watch','https://a.watch.example/2.js'),
		('j3','t-bob','https://a.bob.example/3.js')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO directory_findings (id,target_id,url) VALUES
		('d1','t-deep','https://a.deep.example/admin'),
		('d2','t-watch','https://a.watch.example/admin'),
		('d3','t-bob','https://a.bob.example/admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO backup_findings (id,target_id,url) VALUES
		('b1','t-deep','https://a.deep.example/backup.zip'),
		('b2','t-watch','https://a.watch.example/backup.zip'),
		('b3','t-bob','https://a.bob.example/backup.zip')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO open_redirect_findings (id,target_id,url,status) VALUES
		('o1','t-deep','https://a.deep.example/r?u=1','finding'),
		('o2','t-deep','https://a.deep.example/r?u=2','candidate'),
		('o3','t-watch','https://a.watch.example/r?u=3','rejected'),
		('o4','t-bob','https://a.bob.example/r?u=4','finding')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO nuclei_findings (id,target_id,template_id,verification) VALUES
		('n1','t-deep','xss','verified'),
		('n2','t-deep','sqli','rejected'),
		('n3','t-bob','tech-detect','unverified')`); err != nil {
		t.Fatal(err)
	}

	adminStats := readStats(adminSID)
	if adminStats.Targets != 3 || adminStats.WatchTargets != 2 || adminStats.DeepTargets != 1 ||
		adminStats.Subdomains != 4 || adminStats.AliveHosts != 3 || adminStats.WatchSubdomains != 2 || adminStats.DeepSubdomains != 2 ||
		adminStats.WatchAliveHosts != 2 || adminStats.DeepAliveHosts != 1 ||
		adminStats.HTTPServices != 3 || adminStats.WatchHTTPServices != 2 || adminStats.DeepHTTPServices != 1 ||
		adminStats.Parameters != 3 || adminStats.ReflectedParameters != 2 ||
		adminStats.RunningTasks != 2 || adminStats.FinishedTasks != 1 || adminStats.FailedTasks != 1 || adminStats.PendingTasks != 1 ||
		adminStats.WatchRunningTasks != 1 || adminStats.DeepRunningTasks != 1 ||
		adminStats.WatchFailedTasks != 1 || adminStats.DeepFailedTasks != 0 ||
		adminStats.JSFiles != 3 || adminStats.DirectoryFindings != 3 || adminStats.BackupFindings != 3 ||
		adminStats.OpenRedirectFindings != 2 || adminStats.NucleiFindings != 2 || adminStats.VulnFindings != 2 {
		t.Fatalf("unexpected admin stats: %+v", adminStats)
	}

	bobStats := readStats(bobSID)
	if bobStats.Targets != 1 || bobStats.WatchTargets != 1 || bobStats.DeepTargets != 0 ||
		bobStats.Subdomains != 1 || bobStats.AliveHosts != 1 ||
		bobStats.WatchSubdomains != 1 || bobStats.WatchAliveHosts != 1 ||
		bobStats.HTTPServices != 1 || bobStats.WatchHTTPServices != 1 ||
		bobStats.Parameters != 1 || bobStats.ReflectedParameters != 1 ||
		bobStats.PendingTasks != 1 || bobStats.RunningTasks != 0 ||
		bobStats.JSFiles != 1 || bobStats.DirectoryFindings != 1 || bobStats.BackupFindings != 1 ||
		bobStats.OpenRedirectFindings != 1 || bobStats.NucleiFindings != 1 || bobStats.VulnFindings != 1 {
		t.Fatalf("unexpected bob stats: %+v", bobStats)
	}

	// Zero-target member remains zero even when other users have data.
	if got := readStats(zeroSID); got != (models.DashboardStats{}) {
		t.Fatalf("zero-target member stats with populated DB = %+v, want zero struct", got)
	}
}
