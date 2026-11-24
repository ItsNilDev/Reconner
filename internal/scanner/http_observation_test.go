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
