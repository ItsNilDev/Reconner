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
	"github.com/recon-platform/internal/config"
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
