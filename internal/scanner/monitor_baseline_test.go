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

func TestMonitorHashOnlyJSAndCSSChangesDoNotAlertBellOrTelegram(t *testing.T) {
	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "app.example.test"); err != nil {
		t.Fatal(err)
	}

	type broadcastEvent struct {
		eventType string
		payload   map[string]any
	}
	var events []broadcastEvent
	s := &MonitorScanner{
		db: db,
		broadcast: func(eventType string, payload any) {
			m, _ := payload.(map[string]any)
			events = append(events, broadcastEvent{eventType: eventType, payload: m})
		},
	}

	// Non-alertable changes: hash-only JS/CSS changes and stylesheet attribute churn.
	if err := s.recordChange(targetID, "https://app.example.test/static/app.js", "js_change",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "medium"); err != nil {
		t.Fatalf("recordChange js_change: %v", err)
	}
	if err := s.recordChange(targetID, "https://app.example.test/static/site.css", "css_change",
		"11111111111111111111111111111111", "22222222222222222222222222222222", "low"); err != nil {
		t.Fatalf("recordChange css_change: %v", err)
	}
	if err := s.recordChange(targetID, "https://app.example.test/", "security:stylesheet_added",
		"", "https://cdn.example.test/site.css", "low"); err != nil {
		t.Fatalf("recordChange security:stylesheet_added: %v", err)
	}

	var changeCount, notifCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changeCount); err != nil {
		t.Fatal(err)
	}
	if changeCount != 3 {
		t.Fatalf("monitoring_changes count=%d, want 3", changeCount)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id=?`, targetID).Scan(&notifCount); err != nil {
		t.Fatal(err)
	}
	if notifCount != 0 {
		t.Fatalf("notifications count=%d after JS/CSS/stylesheet changes, want 0", notifCount)
	}

	changesWritten := 0
	notifBroadcasts := 0
	for _, ev := range events {
		switch ev.eventType {
		case "changes_written":
			changesWritten++
		case "notification_created":
			notifBroadcasts++
		}
	}
	if changesWritten != 3 {
		t.Fatalf("changes_written broadcasts=%d, want 3", changesWritten)
	}
	if notifBroadcasts != 0 {
		t.Fatalf("notification_created broadcasts=%d after JS/CSS/stylesheet changes, want 0", notifBroadcasts)
	}

	// Actionable security & header regressions MUST alert both Bell and Telegram broadcast.
	if err := s.recordChange(targetID, "https://app.example.test/", "security:script_added",
		"", "https://evil.example.net/hook.js", "high"); err != nil {
		t.Fatalf("recordChange security:script_added: %v", err)
	}
	if err := s.recordChange(targetID, "https://app.example.test/", "security_header_removed",
		"Content-Security-Policy", "", "high"); err != nil {
		t.Fatalf("recordChange security_header_removed: %v", err)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changeCount); err != nil {
		t.Fatal(err)
	}
	if changeCount != 5 {
		t.Fatalf("monitoring_changes count=%d, want 5", changeCount)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id=?`, targetID).Scan(&notifCount); err != nil {
		t.Fatal(err)
	}
	if notifCount != 2 {
		t.Fatalf("notifications count=%d after actionable security changes, want 2", notifCount)
	}

	var alertedTypes []string
	changesWritten = 0
	for _, ev := range events {
		switch ev.eventType {
		case "changes_written":
			changesWritten++
		case "notification_created":
			if typ, ok := ev.payload["type"].(string); ok {
				alertedTypes = append(alertedTypes, typ)
			}
		}
	}
	if changesWritten != 5 {
		t.Fatalf("changes_written broadcasts=%d, want 5", changesWritten)
	}
	if len(alertedTypes) != 2 || alertedTypes[0] != "security:script_added" || alertedTypes[1] != "security_header_removed" {
		t.Fatalf("notification_created types=%v, want [security:script_added security_header_removed]", alertedTypes)
	}

	// Verify insertChangeTx directly for HTTP status transitions vs hash-only js_change.
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	jsRec, err := insertChangeTx(ctx, tx, targetID, "https://app.example.test/bundle.js", "js_change", "deadbeef", "cafebabe", "medium")
	if err != nil {
		t.Fatalf("insertChangeTx js_change: %v", err)
	}
	if jsRec.alertable {
		t.Fatal("insertChangeTx marked hash-only js_change alertable, want false")
	}
	statusRec, err := insertChangeTx(ctx, tx, targetID, "https://app.example.test/admin", "http_change", "status=403 title=Forbidden", "status=200 title=Admin", "medium")
	if err != nil {
		t.Fatalf("insertChangeTx http_change: %v", err)
	}
	if !statusRec.alertable {
		t.Fatal("insertChangeTx marked 403->200 http_change non-alertable, want true")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorProjectAssetsBodyOnlyEmitsContentChangeAndJSUpsertsJSFiles(t *testing.T) {
	var mu sync.RWMutex
	pageBody := `<html><head><title>Portal</title></head><body>version 1</body></html>`
	jsBody := `console.log("v1");`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		pb, jb := pageBody, jsBody
		mu.RUnlock()
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(jb))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(pb))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	ctx := context.Background()
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL); err != nil {
		t.Fatal(err)
	}
	pageAssetID := uuid.NewString()
	jsAssetID := uuid.NewString()
	jsURL := srv.URL + "/app.js"
	if _, err := db.Exec(`INSERT INTO assets(id,target_id,value,kind,asset_type,approval_status,monitor_enabled,metadata)
		VALUES(?,?,?,?,?,?,1,'{}'),(?,?,?,?,?,?,1,'{}')`,
		pageAssetID, targetID, srv.URL+"/", "web", "url", "approved",
		jsAssetID, targetID, jsURL, "web", "js", "approved"); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}

	// Pass 1: establish baselines (page metadata + js_files capture).
	changed, err := s.monitorProjectAssets(ctx, targetID, "", nil, map[string]bool{}, map[string]bool{}, logFn)
	if err != nil {
		t.Fatalf("pass 1 failed: %v", err)
	}
	if changed != 0 {
		t.Fatalf("pass 1 changed=%d, want 0", changed)
	}

	var firstHash, firstBody string
	if err := db.QueryRow(`SELECT hash, body FROM js_files WHERE target_id=? AND url=?`, targetID, jsURL).Scan(&firstHash, &firstBody); err != nil {
		t.Fatalf("pass 1 did not upsert js_files row: %v", err)
	}
	if firstHash == "" || firstBody != `console.log("v1");` {
		t.Fatalf("pass 1 js_files mismatch: hash=%q body=%q", firstHash, firstBody)
	}

	// Pass 2: body-only page change (same status 200 and same title "Portal") + JS content change.
	mu.Lock()
	pageBody = `<html><head><title>Portal</title></head><body>version 2 completely updated body</body></html>`
	jsBody = `console.log("v2");`
	mu.Unlock()

	changed, err = s.monitorProjectAssets(ctx, targetID, "", nil, map[string]bool{}, map[string]bool{}, logFn)
	if err != nil {
		t.Fatalf("pass 2 failed: %v", err)
	}
	if changed != 2 {
		t.Fatalf("pass 2 changed=%d, want 2 (1 content_change + 1 js_change)", changed)
	}

	// Verify HTML body-only change emitted content_change (NOT page_change).
	var contentCount, pageCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='content_change'`, targetID).Scan(&contentCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='page_change'`, targetID).Scan(&pageCount)
	if contentCount != 1 || pageCount != 0 {
		t.Fatalf("body-only asset change emitted content_change=%d page_change=%d, want 1/0", contentCount, pageCount)
	}

	// Verify js_files rolled old_hash/old_body and stored new hash/body for Diff viewer.
	var newHash, newBody, oldHash, oldBody string
	if err := db.QueryRow(`SELECT hash, body, old_hash, old_body FROM js_files WHERE target_id=? AND url=?`, targetID, jsURL).Scan(&newHash, &newBody, &oldHash, &oldBody); err != nil {
		t.Fatalf("pass 2 js_files query failed: %v", err)
	}
	if oldHash != firstHash || oldBody != `console.log("v1");` || newHash == firstHash || newBody != `console.log("v2");` {
		t.Fatalf("js_files diff roll mismatch: old=%q/%q new=%q/%q", oldHash, oldBody, newHash, newBody)
	}
}

func TestMonitorRunSuppressesSameDestinationRedirectFlip(t *testing.T) {
	var mu sync.RWMutex
	status := http.StatusFound
	location := "https://other-host.example.test/login?state=aaa"
	body := `<html><head><title>302 Found</title></head><body>302 Found</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		st, loc, b := status, location, body
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Location", loc)
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
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,source,probe_tier)
		VALUES(?,?,?,302,'302 Found','probe','deep')`, uuid.NewString(), targetID, serviceURL); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}

	// Pass 1: establishes ObservationMonitor baseline (302 -> https://other-host.example.test/login).
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	// Pass 2: flips 302 -> 301 to the same normalized destination with boilerplate title.
	mu.Lock()
	status = http.StatusMovedPermanently
	location = "https://OTHER-HOST.EXAMPLE.TEST:443/login?state=bbb#frag"
	body = `<html><head><title>301 Moved Permanently</title></head><body>301 Moved Permanently</body></html>`
	mu.Unlock()
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changes)
	if changes != 0 {
		t.Fatalf("same-destination 302->301 flip in monitor emitted %d changes, want 0", changes)
	}
	var baseStatus int
	var baseRedir string
	_ = db.QueryRow(`SELECT status_code, redirect_url FROM http_observation_baselines WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, baselineURL, ObservationMonitor).Scan(&baseStatus, &baseRedir)
	if baseStatus != 302 || baseRedir != "https://other-host.example.test/login" {
		t.Fatalf("monitor baseline mismatch: status=%d redirect=%q", baseStatus, baseRedir)
	}

	// Pass 3: flips destination to /app -> MUST emit http_change!
	mu.Lock()
	status = http.StatusMovedPermanently
	location = "https://other-host.example.test/app"
	mu.Unlock()
	if err := s.Run(ctx, targetID, logFn); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='http_change'`, targetID).Scan(&changes)
	if changes != 1 {
		t.Fatalf("destination-changed 302->301 emitted %d http_change rows, want 1", changes)
	}
}
