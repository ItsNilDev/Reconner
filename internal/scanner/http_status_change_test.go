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
		WHERE target_id=? AND change_type='http_change'`, tid).Scan(&oldStatus, &newStatus, &oldValue, &newValue); err != nil {
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
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='http_change'`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("change rows=%d, want 1 (duplicate transition recorded)", n)
	}
}
