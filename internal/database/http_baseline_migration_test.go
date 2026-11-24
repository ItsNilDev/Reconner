package database

import (
	"path/filepath"
	"testing"
)

// The per-observation baseline table is additive. A fresh database and an
// upgraded database must both accept it, and repeat migrations must not lose
// recorded baselines or prior scope/observation rows.
func TestHTTPObservationBaselineMigrationIsAdditive(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-update fixture: the baseline table does not exist yet,
	// but older scope and observation rows are already present.
	if _, err := db.Exec(`DROP TABLE http_observation_baselines`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain,exclude_scope) VALUES ('t1','example.test','manual.example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source,probe_tier)
		VALUES ('s1','t1','https://example.test/',200,'probe','deep')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_observation_baselines
		(target_id,service_url,observation_type,status_code,title)
		VALUES ('t1','https://example.test/','deep_http',200,'OK')`); err != nil {
		t.Fatal(err)
	}
	// Server startup runs migrations again. Nothing may be dropped.
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_observation_baselines WHERE target_id='t1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("baselines after repeat migration = %d, want 1", count)
	}
	var exclude, status string
	if err := db.QueryRow(`SELECT exclude_scope FROM targets WHERE id='t1'`).Scan(&exclude); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status_code FROM http_services WHERE id='s1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if exclude != "manual.example.test" || status != "200" {
		t.Fatalf("prior data lost: exclude=%q status=%q", exclude, status)
	}
}
