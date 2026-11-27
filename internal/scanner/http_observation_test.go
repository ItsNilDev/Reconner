package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func newObservationTestScanner(t *testing.T) (*HTTPScanner, *database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "obs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	return NewHTTPScanner(db, nil, &config.Config{}, logger.New("error")), db, targetID
}

func TestObservationBaselinesArePerType(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := WithTaskID(context.Background(), "round-1")
	url := "https://a.example.test/login?next=/x"

	// A breadth 302 and a deep 200 establish independent baselines.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: url, StatusCode: 302,
		Title: "Redirect", ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: url, StatusCode: 200,
		Title: "OK", ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, tid).Scan(&n)
	if n != 0 {
		t.Fatalf("cross-tier observation created %d deep events", n)
	}

	// A real breadth transition is written with its task id and numeric codes.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: url, StatusCode: 403,
		Title: "Forbidden", ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}
	var taskID string
	var oldStatus, newStatus int
	err := db.QueryRow(`SELECT task_id,old_status,new_status FROM watch_round_changes
		WHERE target_id=? AND change_type='status_change'`, tid).Scan(&taskID, &oldStatus, &newStatus)
	if err != nil {
		t.Fatalf("missing breadth status event: %v", err)
	}
	if taskID != "round-1" || oldStatus != 302 || newStatus != 403 {
		t.Fatalf("event task=%q codes=%d->%d", taskID, oldStatus, newStatus)
	}

	// An unchanged repeat emits nothing; a later recurrence emits a fresh row.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: url, StatusCode: 403,
		Title: "Forbidden", ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: url, StatusCode: 200,
		Title: "OK", ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes
		WHERE target_id=? AND change_type='status_change'`, tid).Scan(&n)
	if n != 2 {
		t.Fatalf("status events=%d, want 2", n)
	}
}

func TestRecordObservationRetriesAfterFailedEventWrite(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	url := "https://b.example.test/"
	mk := func(code int, title string) HTTPObservation {
		return HTTPObservation{TargetID: tid, URL: url, StatusCode: code, Title: title,
			ProbeTier: "deep", Type: ObservationDeep}
	}
	if err := s.recordObservation(ctx, mk(200, "OK")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_monitor_event BEFORE INSERT ON monitoring_changes
		BEGIN SELECT RAISE(ABORT, 'forced event failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, mk(403, "Forbidden")); err == nil {
		t.Fatal("event write failure did not surface")
	}
	var code int
	_ = db.QueryRow(`SELECT status_code FROM http_observation_baselines
		WHERE target_id=? AND observation_type=?`, tid, ObservationDeep).Scan(&code)
	if code != 200 {
		t.Fatalf("baseline advanced to %d without its event", code)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_monitor_event`); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, mk(403, "Forbidden")); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	_ = db.QueryRow(`SELECT status_code FROM http_observation_baselines
		WHERE target_id=? AND observation_type=?`, tid, ObservationDeep).Scan(&code)
	if code != 403 {
		t.Fatalf("baseline=%d after retry, want 403", code)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&code)
	if code != 1 {
		t.Fatalf("events after retry=%d, want 1", code)
	}
}

func TestNormalizeServiceURLKeepsPortPathAndQuery(t *testing.T) {
	cases := map[string]string{
		"https://A.Example.Test./a/b?q=1": "https://a.example.test/a/b?q=1",
		"http://a.example.test:8443/x":    "http://a.example.test:8443/x",
		"https://a.example.test":          "https://a.example.test/",
		"https://a.example.test/a#frag":   "https://a.example.test/a",
	}
	for raw, want := range cases {
		if got := NormalizeServiceURL(raw); got != want {
			t.Errorf("NormalizeServiceURL(%q)=%q, want %q", raw, got, want)
		}
	}
}

func TestStatusZeroObservationLeavesBaselineAndInventoryIntact(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	rawURL := "https://zero.example.test/"
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 200, Title: "OK",
		Type: ObservationDeep, ProbeTier: "deep", Source: "probe",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 0, Title: "",
		Type: ObservationDeep, ProbeTier: "deep", Source: "probe",
	}); err != nil {
		t.Fatal(err)
	}
	var status int
	var title string
	if err := db.QueryRow(`SELECT status_code,title FROM http_services WHERE target_id=? AND url=?`, tid, NormalizeServiceURL(rawURL)).Scan(&status, &title); err != nil {
		t.Fatal(err)
	}
	if status != 200 || title != "OK" {
		t.Fatalf("inventory = %d/%q, want 200/OK", status, title)
	}
	var events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, tid).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("status-zero created %d events, want 0", events)
	}
}

func TestObservationUpgradesSeedAndKeepsSubdomainLink(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	rawURL := "https://seed.example.test/"
	subID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO subdomains(id,target_id,subdomain) VALUES(?,?,?)`, subID, tid, "seed.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,subdomain_id,url,status_code,source)
		VALUES(?,?,?,?,0,'seed')`, uuid.NewString(), tid, subID, NormalizeServiceURL(rawURL)); err != nil {
		t.Fatal(err)
	}
	if err := s.recordObservation(context.Background(), HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 200, Title: "OK",
		Type: ObservationDeep, ProbeTier: "deep", Source: "probe",
	}); err != nil {
		t.Fatal(err)
	}
	var source, linked string
	var status int
	if err := db.QueryRow(`SELECT COALESCE(source,''),COALESCE(subdomain_id,''),status_code
		FROM http_services WHERE target_id=? AND url=?`, tid, NormalizeServiceURL(rawURL)).Scan(&source, &linked, &status); err != nil {
		t.Fatal(err)
	}
	if source != "probe" || linked != subID || status != 200 {
		t.Fatalf("inventory = %q/%q/%d, want probe/%s/200", source, linked, status, subID)
	}
}

func TestOnlyStatusChangeWritesBellEntry(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	rawURL := "https://bell.example.test/"
	base := HTTPObservation{TargetID: tid, URL: rawURL, StatusCode: 200, Title: "OK", Type: ObservationDeep, ProbeTier: "deep", Source: "probe"}
	if err := s.recordObservation(ctx, base); err != nil {
		t.Fatal(err)
	}
	statusObs := base
	statusObs.StatusCode = 403
	statusObs.Title = "Forbidden"
	if err := s.recordObservation(ctx, statusObs); err != nil {
		t.Fatal(err)
	}
	var bells int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id=?`, tid).Scan(&bells); err != nil {
		t.Fatal(err)
	}
	if bells != 1 {
		t.Fatalf("bells after status change = %d, want 1", bells)
	}
	pageObs := statusObs
	pageObs.Title = "Different title"
	if err := s.recordObservation(ctx, pageObs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id=?`, tid).Scan(&bells); err != nil {
		t.Fatal(err)
	}
	if bells != 1 {
		t.Fatalf("bells after page change = %d, want 1", bells)
	}
	var changes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='page_change'`, tid).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Fatalf("page_change rows = %d, want 2", changes)
	}
}

func TestNormalizeRedirectTarget(t *testing.T) {
	cases := []struct {
		base string
		raw  string
		want string
	}{
		{"https://hey.com/", "/login?state=abc123&nonce=xyz#top", "https://hey.com/login"},
		{"https://hey.com/", "//www.hey.com:443/app?csrf=tok", "https://www.hey.com/app"},
		{"http://hey.com/", "http://HEY.COM.:80", "http://hey.com/"},
		{"https://hey.com/", "https://HEY.COM:443/login?state=different", "https://hey.com/login"},
		{"https://hey.com/", "https://other.example.test:8443/auth?code=1", "https://other.example.test:8443/auth"},
		{"https://hey.com/v1/start", "next?state=1", "https://hey.com/v1/next"},
		{"https://hey.com/", "   ", ""},
	}
	for _, tc := range cases {
		if got := normalizeRedirectTarget(tc.base, tc.raw); got != tc.want {
			t.Errorf("normalizeRedirectTarget(%q, %q) = %q, want %q", tc.base, tc.raw, got, tc.want)
		}
	}
}

func TestEquivalentRedirectStatusSuppressionAndBoilerplateTitle(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := WithTaskID(context.Background(), "round-1")
	rawURL := "https://hey.example.test/"

	// Initial 302 -> /login?state=1
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: rawURL, StatusCode: 302,
		Title: "302 Found", RedirectURL: "https://hey.example.test/login?state=111",
		Server: "cloudflare", Technologies: `["Cloudflare"]`,
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	// Flip 302 -> 301 with same normalized destination (different volatile OAuth query + default :443 + boilerplate title)
	effStatus, err := s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-2", URL: rawURL, StatusCode: 301,
		Title: "301 Moved Permanently", RedirectURL: "https://HEY.EXAMPLE.TEST:443/login?state=222#frag",
		Server: "cloudflare", Technologies: `["Cloudflare"]`,
		ProbeTier: "watch", Type: ObservationWatch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effStatus != 302 {
		t.Fatalf("effectiveStatus=%d, want pinned 302", effStatus)
	}

	// Flip back 301 -> 302 (or 302 again) must also emit zero events.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-3", URL: rawURL, StatusCode: 302,
		Title: "Moved Temporarily", RedirectURL: "/login?nonce=333",
		Server: "cloudflare", Technologies: `["Cloudflare"]`,
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	var totalChanges, bells int
	_ = db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id=?`, tid).Scan(&totalChanges)
	_ = db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id=?`, tid).Scan(&bells)
	if totalChanges != 0 || bells != 0 {
		t.Fatalf("same-destination 302<->301 emitted changes=%d bells=%d, want 0/0", totalChanges, bells)
	}

	// Verify both baseline and http_services remained pinned to 302 and "302 Found".
	var baseStatus, svcStatus int
	var baseTitle, svcTitle string
	if err := db.QueryRow(`SELECT status_code, title FROM http_observation_baselines WHERE target_id=? AND service_url=? AND observation_type=?`,
		tid, NormalizeServiceURL(rawURL), ObservationWatch).Scan(&baseStatus, &baseTitle); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status_code, title FROM http_services WHERE target_id=? AND url=?`,
		tid, NormalizeServiceURL(rawURL)).Scan(&svcStatus, &svcTitle); err != nil {
		t.Fatal(err)
	}
	if baseStatus != 302 || svcStatus != 302 || baseTitle != "302 Found" || svcTitle != "302 Found" {
		t.Fatalf("pinned state mismatch: baseline=%d/%q svc=%d/%q", baseStatus, baseTitle, svcStatus, svcTitle)
	}

	// Also verify 301 -> 302 direction on a separate URL.
	rawURL2 := "https://hey2.example.test/"
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: rawURL2, StatusCode: 301,
		Title: "301 Moved Permanently", RedirectURL: "https://hey2.example.test/home",
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}
	eff2, err := s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-2", URL: rawURL2, StatusCode: 302,
		Title: "302 Found", RedirectURL: "/home?state=fresh",
		ProbeTier: "watch", Type: ObservationWatch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff2 != 301 {
		t.Fatalf("301->302 effectiveStatus=%d, want pinned 301", eff2)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id=?`, tid).Scan(&totalChanges)
	if totalChanges != 0 {
		t.Fatalf("301->302 emitted changes=%d, want 0", totalChanges)
	}
}

func TestSilentUpgradeBackfillOfEmptyRedirectBaseline(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := WithTaskID(context.Background(), "round-upgrade")
	rawURL := "https://legacy.example.test/"

	// Pre-upgrade 301 baseline with empty redirect_url.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-0", URL: rawURL, StatusCode: 301,
		Title: "301 Moved Permanently", RedirectURL: "",
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	// Post-upgrade probe observes 302 with Location populated -> must backfill silently with zero events.
	effStatus, err := s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: rawURL, StatusCode: 302,
		Title: "302 Found", RedirectURL: "https://www.legacy.example.test/",
		ProbeTier: "watch", Type: ObservationWatch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effStatus != 301 {
		t.Fatalf("effectiveStatus=%d, want pinned 301", effStatus)
	}

	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id=?`, tid).Scan(&changes)
	if changes != 0 {
		t.Fatalf("silent backfill emitted %d changes, want 0", changes)
	}

	var baseRedir, svcRedir string
	_ = db.QueryRow(`SELECT redirect_url FROM http_observation_baselines WHERE target_id=? AND service_url=? AND observation_type=?`,
		tid, NormalizeServiceURL(rawURL), ObservationWatch).Scan(&baseRedir)
	_ = db.QueryRow(`SELECT redirect_url FROM http_services WHERE target_id=? AND url=?`,
		tid, NormalizeServiceURL(rawURL)).Scan(&svcRedir)
	if baseRedir != "https://www.legacy.example.test/" || svcRedir != "https://www.legacy.example.test/" {
		t.Fatalf("redirect_url not backfilled: baseline=%q svc=%q", baseRedir, svcRedir)
	}
}

func TestDestinationChangedRedirectEmitsStatusAndRedirectChanges(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := WithTaskID(context.Background(), "round-1")
	rawURL := "https://move.example.test/"

	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-1", URL: rawURL, StatusCode: 302,
		Title: "302 Found", RedirectURL: "https://move.example.test/login",
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	// Destination changed from /login to /app AND status changed 302 -> 301.
	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, TaskID: "round-2", URL: rawURL, StatusCode: 301,
		Title: "301 Moved Permanently", RedirectURL: "https://move.example.test/app",
		ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	var statusOld, statusNew int
	if err := db.QueryRow(`SELECT old_status, new_status FROM watch_round_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&statusOld, &statusNew); err != nil {
		t.Fatalf("missing status_change row: %v", err)
	}
	if statusOld != 302 || statusNew != 301 {
		t.Fatalf("status_change codes=%d->%d, want 302->301", statusOld, statusNew)
	}

	var redirOld, redirNew int
	var oldVal, newVal string
	if err := db.QueryRow(`SELECT old_status, new_status, old_value, new_value FROM watch_round_changes WHERE target_id=? AND change_type='redirect_change'`, tid).Scan(&redirOld, &redirNew, &oldVal, &newVal); err != nil {
		t.Fatalf("missing redirect_change row: %v", err)
	}
	if redirOld != 302 || redirNew != 301 {
		t.Fatalf("redirect_change status codes=%d->%d, want 302->301", redirOld, redirNew)
	}
	if oldVal != "https://move.example.test/login" || newVal != "https://move.example.test/app" {
		t.Fatalf("redirect_change values=%q -> %q", oldVal, newVal)
	}
}

func TestPinBaselineStatusUpdatesTechWithoutStatusChange(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	rawURL := "https://pin.example.test/"

	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 200, Title: "Home",
		Server: "nginx", Technologies: `["Nginx"]`,
		ProbeTier: "deep", Type: ObservationDeep,
	}); err != nil {
		t.Fatal(err)
	}

	// Unconfirmed transient 503 with updated server/tech and PinBaselineStatus=true.
	effStatus, err := s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 503, Title: "Home",
		Server: "cloudflare", Technologies: `["Cloudflare"]`,
		ProbeTier: "deep", Type: ObservationDeep, PinBaselineStatus: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effStatus != 200 {
		t.Fatalf("effectiveStatus=%d, want pinned 200", effStatus)
	}

	var statusChanges, techChanges int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&statusChanges)
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='tech_change'`, tid).Scan(&techChanges)
	if statusChanges != 0 {
		t.Fatalf("status_change count=%d, want 0", statusChanges)
	}
	if techChanges != 1 {
		t.Fatalf("tech_change count=%d, want 1", techChanges)
	}

	var baseStatus, svcStatus int
	var baseServer, svcServer string
	_ = db.QueryRow(`SELECT status_code, server FROM http_observation_baselines WHERE target_id=? AND service_url=? AND observation_type=?`,
		tid, NormalizeServiceURL(rawURL), ObservationDeep).Scan(&baseStatus, &baseServer)
	_ = db.QueryRow(`SELECT status_code, server FROM http_services WHERE target_id=? AND url=?`,
		tid, NormalizeServiceURL(rawURL)).Scan(&svcStatus, &svcServer)
	if baseStatus != 200 || svcStatus != 200 || baseServer != "cloudflare" || svcServer != "cloudflare" {
		t.Fatalf("pinned baseline/inventory mismatch: base=%d/%q svc=%d/%q", baseStatus, baseServer, svcStatus, svcServer)
	}
}

func TestPinBaselineStatusPreservesHealthyTitleOnTransientErrorPage(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()
	rawURL := "https://portal.example.test/"

	if err := s.recordObservation(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 200, Title: "Portal",
		Server: "nginx", ProbeTier: "watch", Type: ObservationWatch,
	}); err != nil {
		t.Fatal(err)
	}

	effStatus, err := s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID: tid, URL: rawURL, StatusCode: 503, Title: "503 Service Temporarily Unavailable",
		Server: "nginx", ProbeTier: "watch", Type: ObservationWatch, PinBaselineStatus: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if effStatus != 200 {
		t.Fatalf("effectiveStatus=%d, want 200", effStatus)
	}

	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE target_id=?`, tid).Scan(&changes)
	if changes != 0 {
		t.Fatalf("watch_round_changes count=%d, want 0", changes)
	}
	var title string
	_ = db.QueryRow(`SELECT title FROM http_services WHERE target_id=? AND url=?`, tid, NormalizeServiceURL(rawURL)).Scan(&title)
	if title != "Portal" {
		t.Fatalf("http_services.title=%q, want Portal", title)
	}
}
