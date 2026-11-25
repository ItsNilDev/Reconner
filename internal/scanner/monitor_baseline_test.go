package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/models"
)

func TestMonitorProjectAssetsHandlesEmptyMetadataString(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>empty meta</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	assetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets(id,target_id,value,kind,asset_type,approval_status,monitor_enabled,metadata)
		VALUES(?,?,?,?,?,?,1,'')`,
		assetID, targetID, srv.URL, "web", "url", "approved"); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	changed, err := s.monitorProjectAssets(context.Background(), targetID, "", nil,
		map[string]bool{}, map[string]bool{}, func(string, string, string) {})
	if err != nil {
		t.Fatalf("monitorProjectAssets failed on empty metadata: %v", err)
	}
	if changed != 0 {
		t.Fatalf("initial baseline pass raised %d changes, want 0", changed)
	}
	mu.Lock()
	gotHits := hits
	mu.Unlock()
	if gotHits == 0 {
		t.Fatal("asset with empty-string metadata was never fetched")
	}
	var updatedMeta string
	if err := db.QueryRow(`SELECT metadata FROM assets WHERE id=?`, assetID).Scan(&updatedMeta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updatedMeta, "monitor_hash") {
		t.Fatalf("expected updated monitor metadata, got %q", updatedMeta)
	}
}

func TestMonitorWatchTierEstablishesMonitorBaselineWithoutFalseTransitionOrDeepOverwrite(t *testing.T) {
	var mu sync.RWMutex
	status := http.StatusOK
	title := "Home"
	body := `<html><head><title>Home</title></head><body>v1</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		st, b := status, body
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	ctx := context.Background()
	targetID := uuid.NewString()
	serviceURL := srv.URL + "/"
	baselineURL := NormalizeServiceURL(serviceURL)

	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL); err != nil {
		t.Fatal(err)
	}
	// Seed a watch-tier http_services row with 302 (e.g. unfollowed redirect)
	// and an existing ObservationDeep baseline that must never be overwritten by MonitorScanner.
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,source,probe_tier)
		VALUES(?,?,?,302,'Redirect','probe','watch')`,
		uuid.NewString(), targetID, serviceURL); err != nil {
		t.Fatal(err)
	}
	if err := upsertObservationBaseline(ctx, db, targetID, baselineURL,
		ObservationDeep, 418, "DeepOriginal", "deep-srv", "[]", "", "deep-hash"); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}

	// Pass 1: monitor observes 200 against a watch-tier 302 row.
	// Must establish ObservationMonitor silently with zero changes and leave ObservationDeep intact.
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var changeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changeCount); err != nil {
		t.Fatal(err)
	}
	if changeCount != 0 {
		t.Fatalf("first monitor pass against watch-tier row emitted %d changes, want 0", changeCount)
	}

	var monStatus int
	var monTitle, monHash string
	if err := db.QueryRow(`SELECT status_code, title, body_hash FROM http_observation_baselines
		WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, baselineURL, ObservationMonitor).Scan(&monStatus, &monTitle, &monHash); err != nil {
		t.Fatalf("ObservationMonitor baseline was not established: %v", err)
	}
	if monStatus != 200 || monTitle != title || monHash == "" {
		t.Fatalf("unexpected ObservationMonitor baseline: status=%d title=%q hash=%q", monStatus, monTitle, monHash)
	}

	var deepStatus int
	var deepTitle, deepHash string
	if err := db.QueryRow(`SELECT status_code, title, body_hash FROM http_observation_baselines
		WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, baselineURL, ObservationDeep).Scan(&deepStatus, &deepTitle, &deepHash); err != nil {
		t.Fatalf("ObservationDeep baseline missing: %v", err)
	}
	if deepStatus != 418 || deepTitle != "DeepOriginal" || deepHash != "deep-hash" {
		t.Fatalf("MonitorScanner overwrote ObservationDeep: status=%d title=%q hash=%q", deepStatus, deepTitle, deepHash)
	}

	// Pass 2: body-only change (same status 200 and same title) must emit content_change with hashes.
	mu.Lock()
	body = `<html><head><title>Home</title></head><body>v2 completely different body</body></html>`
	mu.Unlock()
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var changeType, oldVal, newVal string
	if err := db.QueryRow(`SELECT change_type, old_value, new_value FROM monitoring_changes
		WHERE target_id=? ORDER BY detected_at DESC LIMIT 1`, targetID).Scan(&changeType, &oldVal, &newVal); err != nil {
		t.Fatalf("expected content_change row: %v", err)
	}
	if changeType != "content_change" {
		t.Fatalf("body-only change emitted change_type=%q, want content_change", changeType)
	}
	if oldVal != monHash || newVal == "" || newVal == oldVal {
		t.Fatalf("content_change hashes invalid: old=%q new=%q (baseline=%q)", oldVal, newVal, monHash)
	}

	// Verify ObservationDeep is STILL untouched after pass 2.
	if err := db.QueryRow(`SELECT status_code, title, body_hash FROM http_observation_baselines
		WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, baselineURL, ObservationDeep).Scan(&deepStatus, &deepTitle, &deepHash); err != nil {
		t.Fatal(err)
	}
	if deepStatus != 418 || deepTitle != "DeepOriginal" || deepHash != "deep-hash" {
		t.Fatalf("MonitorScanner overwrote ObservationDeep on pass 2: status=%d title=%q hash=%q", deepStatus, deepTitle, deepHash)
	}
}

func TestMonitorDoesNotAdvanceBaselineWhenRecordChangeFails(t *testing.T) {
	var mu sync.RWMutex
	status := http.StatusOK
	body := `<html><head><title>OK</title></head><body>initial</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		st, b := status, body
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	ctx := context.Background()
	targetID := uuid.NewString()
	serviceID := uuid.NewString()
	serviceURL := srv.URL + "/"
	baselineURL := NormalizeServiceURL(serviceURL)

	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,source,probe_tier)
		VALUES(?,?,?,200,'OK','probe','deep')`, serviceID, targetID, serviceURL); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TRIGGER fail_monitoring_changes BEFORE INSERT ON monitoring_changes
		BEGIN SELECT RAISE(ABORT, 'forced write error'); END`); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	status = http.StatusInternalServerError
	body = `<html><head><title>Error</title></head><body>boom</body></html>`
	mu.Unlock()

	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var svcStatus, monStatus int
	if err := db.QueryRow(`SELECT status_code FROM http_services WHERE id=?`, serviceID).Scan(&svcStatus); err != nil {
		t.Fatal(err)
	}
	if svcStatus != 200 {
		t.Fatalf("http_services advanced to %d despite recordChange failure", svcStatus)
	}
	if err := db.QueryRow(`SELECT status_code FROM http_observation_baselines
		WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, baselineURL, ObservationMonitor).Scan(&monStatus); err != nil {
		t.Fatal(err)
	}
	if monStatus != 200 {
		t.Fatalf("ObservationMonitor baseline advanced to %d despite recordChange failure", monStatus)
	}
}

func TestStoreBasicServiceResolvesBareLowercaseSubdomain(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	subID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO subdomains(id,target_id,subdomain) VALUES(?,?,?)`,
		subID, tid, "app.example.test"); err != nil {
		t.Fatal(err)
	}
	err := s.storeBasicService(ctx, &models.HTTPService{
		ID:         uuid.NewString(),
		TargetID:   tid,
		URL:        "https://App.Example.Test./",
		StatusCode: 200,
		Title:      "App",
	})
	if err != nil {
		t.Fatalf("storeBasicService failed: %v", err)
	}
	var gotSubID string
	if err := db.QueryRow(`SELECT COALESCE(subdomain_id,'') FROM http_services WHERE target_id=? AND url=?`,
		tid, "https://app.example.test/").Scan(&gotSubID); err != nil {
		t.Fatal(err)
	}
	if gotSubID != subID {
		t.Fatalf("subdomain_id=%q, want %q", gotSubID, subID)
	}
}
