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

// TestStoreHTTPServiceCapturesStatusBaseline proves the probe records the
// before/after status at the write boundary. Without this, http_probe overwrites
// the baseline before monitor runs and the transition is lost (A7).
func TestStoreHTTPServiceCapturesStatusBaseline(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets(id,domain,priority) VALUES(?,?,'medium')`, tid, "app.example.test"); err != nil {
		t.Fatal(err)
	}
	rawURL := "https://app.example.test/"
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,last_seen)
		VALUES(?,?,?,403,'Forbidden',CURRENT_TIMESTAMP)`, uuid.New().String(), tid, rawURL); err != nil {
		t.Fatal(err)
	}

	s := NewHTTPScanner(db, nil, &config.Config{}, logger.New("error"))
	out := httpxOutput{URL: rawURL, StatusCode: 200, Title: "OK"}
	if err := s.storeHTTPService(context.Background(), tid, out); err != nil {
		t.Fatal(err)
	}

	var oldStatus, newStatus int
	var oldValue, newValue string
	if err := db.QueryRow(`SELECT old_status,new_status,old_value,new_value FROM monitoring_changes
		WHERE target_id=? AND change_type='status_change'`, tid).Scan(&oldStatus, &newStatus, &oldValue, &newValue); err != nil {
		t.Fatalf("no status change row: %v", err)
	}
	if oldStatus != 403 || newStatus != 200 {
		t.Fatalf("codes=%d->%d, want 403->200", oldStatus, newStatus)
	}
	if oldValue == "" || newValue == "" {
		t.Fatalf("values must be populated: %q / %q", oldValue, newValue)
	}

	// A repeated probe with the same status must not create a second change.
	if err := s.storeHTTPService(context.Background(), tid, out); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='status_change'`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("change rows=%d, want 1 (duplicate transition recorded)", n)
	}
}

func TestEffectiveRedirectURLOnlyFallsBackToLocationOn3xx(t *testing.T) {
	// 201 Created with Location header must NOT populate redirect_url.
	got201 := effectiveRedirectURL(httpxOutput{
		URL:        "https://api.example.test/items",
		StatusCode: 201,
		Location:   "/items/42",
	})
	if got201 != "" {
		t.Fatalf("201 Location leaked into redirect_url: %q", got201)
	}

	// 302 with relative Location resolves and strips volatile query params.
	got302 := effectiveRedirectURL(httpxOutput{
		URL:        "https://app.example.test/",
		StatusCode: 302,
		Location:   "/login?state=secret123#frag",
	})
	if got302 != "https://app.example.test/login" {
		t.Fatalf("302 effectiveRedirectURL=%q, want https://app.example.test/login", got302)
	}

	// Explicit final_url takes precedence over location.
	gotFinal := effectiveRedirectURL(httpxOutput{
		URL:         "https://app.example.test/",
		StatusCode:  200,
		RedirectURL: "https://app.example.test/dashboard",
		Location:    "/ignored",
	})
	if gotFinal != "https://app.example.test/dashboard" {
		t.Fatalf("final_url effectiveRedirectURL=%q, want https://app.example.test/dashboard", gotFinal)
	}
}

func TestUpdateSubdomainAliveWithVariantsUpdatesAllCaseAndDotRows(t *testing.T) {
	s, db, tid := newObservationTestScanner(t)
	ctx := context.Background()

	id1, id2 := uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(`INSERT INTO subdomains(id,target_id,subdomain,is_alive) VALUES(?,?,?,0),(?,?,?,0)`,
		id1, tid, "App.Example.Test", id2, tid, "app.example.test."); err != nil {
		t.Fatal(err)
	}
	if err := s.updateSubdomainAliveWithVariants(ctx, tid, "app.example.test",
		[]string{"App.Example.Test", "app.example.test."}, 302, []string{"Cloudflare"}, "cloudflare"); err != nil {
		t.Fatal(err)
	}
	var aliveCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND is_alive=1 AND status_code=302`, tid).Scan(&aliveCount); err != nil {
		t.Fatal(err)
	}
	if aliveCount != 2 {
		t.Fatalf("alive variants=%d, want 2", aliveCount)
	}
}
