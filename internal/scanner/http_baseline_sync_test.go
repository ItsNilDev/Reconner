package scanner

import (
	"context"
	"testing"
)

// Monitor commits its own observation first. A later http_probe with the same
// status must not emit a second event or alert.
func TestMonitorBaselinePreventsDuplicateDeepStatusEvent(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	url := "https://a.example.test/"
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source,probe_tier)
		VALUES ('s1',?,?,200,'OK','probe','deep')`, tid, url); err != nil {
		t.Fatal(err)
	}
	if err := upsertObservationBaseline(ctx, db, tid, NormalizeServiceURL(url), ObservationDeep,
		500, "Server Error", "nginx", "[]", "", "body-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: url, StatusCode: 500, Title: "Server Error",
		Server: "nginx", BodyHash: "body-hash", ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("duplicate status events=%d, want 0", n)
	}
	var code int
	if err := db.QueryRow(`SELECT status_code FROM http_services WHERE target_id=? AND url=?`, tid, url).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code != 500 {
		t.Fatalf("inventory status=%d, want 500", code)
	}
}

// A failed connect reports status 0. That value is unknown and must not erase
// the last valid baseline, or the genuine 200 -> 500 transition is lost.
func TestStatusZeroDoesNotOverwriteObservationBaseline(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	url := "https://b.example.test/"
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: url, StatusCode: 200, Title: "OK",
		ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: url, StatusCode: 0, Title: "",
		ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: url, StatusCode: 500, Title: "Error",
		ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("status_change events=%d, want 1", n)
	}
}

func TestPreloadBaselinesRespectsTierAndPrefersObservationTable(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()

	watchURL := "https://watch.example.test/"
	deepURL := "https://deep.example.test/"
	seedURL := "https://seed.example.test/"
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,redirect_url,source,probe_tier) VALUES
		('s1',?,?,302,'302 Found','https://watch.example.test/login','probe','watch'),
		('s2',?,?,200,'OK','','probe','deep'),
		('s3',?,?,0,'','','seed','watch')`,
		tid, watchURL, tid, deepURL, tid, seedURL); err != nil {
		t.Fatal(err)
	}
	// Explicit watch baseline overrides http_services fallback.
	if err := upsertObservationBaseline(ctx, db, tid, watchURL, ObservationWatch,
		301, "301 Moved Permanently", "cloudflare", `["Cloudflare"]`, "https://watch.example.test/login", ""); err != nil {
		t.Fatal(err)
	}

	watchMap := s.preloadBaselines(ctx, tid, ObservationWatch)
	if b, ok := watchMap[watchURL]; !ok || b.status != 301 || b.redirect != "https://watch.example.test/login" {
		t.Fatalf("watch preload mismatch: ok=%v b=%+v", ok, b)
	}
	if _, ok := watchMap[deepURL]; ok {
		t.Fatalf("watch preload leaked deep-tier http_services row")
	}
	if _, ok := watchMap[seedURL]; ok {
		t.Fatalf("watch preload leaked seed row")
	}

	deepMap := s.preloadBaselines(ctx, tid, ObservationDeep)
	if b, ok := deepMap[deepURL]; !ok || b.status != 200 {
		t.Fatalf("deep preload mismatch: ok=%v b=%+v", ok, b)
	}
	if _, ok := deepMap[watchURL]; ok {
		t.Fatalf("deep preload leaked watch-tier row")
	}
}
