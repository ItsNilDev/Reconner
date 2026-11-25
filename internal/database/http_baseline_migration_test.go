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
	var exclSource, exclProgramID, exclPattern, status string
	if err := db.QueryRow(`SELECT source, program_id, pattern FROM target_exclusions WHERE target_id='t1' AND pattern='manual.example.test'`).Scan(&exclSource, &exclProgramID, &exclPattern); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status_code FROM http_services WHERE id='s1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if exclSource != "manual" || exclProgramID != "" || exclPattern != "manual.example.test" || status != "200" {
		t.Fatalf("prior data lost: exclusion=(%q,%q,%q) status=%q", exclSource, exclProgramID, exclPattern, status)
	}
}

func TestHTTPServiceURLNormalizationMergesBareHostDuplicates(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "normalize.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES ('t1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,last_seen)
		VALUES ('old','t1','https://example.test',0,'','2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,last_seen)
		VALUES ('good','t1','https://example.test/',200,'OK','2026-01-02 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='t1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("services after normalization = %d, want 1", count)
	}
	var id, url string
	var status int
	if err := db.QueryRow(`SELECT id,url,status_code FROM http_services WHERE target_id='t1'`).Scan(&id, &url, &status); err != nil {
		t.Fatal(err)
	}
	if id != "good" || url != "https://example.test/" || status != 200 {
		t.Fatalf("kept service = %s/%s/%d, want good/https://example.test//200", id, url, status)
	}
}

// A newer bare-host duplicate with status 0 must not evict the canonical row
// that has a valid status. A valid status wins over a newer last_seen.
func TestHTTPServiceURLNormalizationKeepsValidStatusOverNewerBareDuplicate(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "normalize-status.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES ('t1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,last_seen)
		VALUES ('bare','t1','https://example.test',0,'','2026-02-02 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,last_seen)
		VALUES ('good','t1','https://example.test/',200,'OK','2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='t1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("services after normalization = %d, want 1", count)
	}
	var id, url string
	var status int
	if err := db.QueryRow(`SELECT id,url,status_code FROM http_services WHERE target_id='t1'`).Scan(&id, &url, &status); err != nil {
		t.Fatal(err)
	}
	if id != "good" || url != "https://example.test/" || status != 200 {
		t.Fatalf("kept service = %s/%s/%d, want good/https://example.test//200", id, url, status)
	}
}

func TestNormalizeHTTPServiceURLsPreservesCrossTargetRows(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "normalize-cross-target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES ('target-a','a.example.test'),('target-b','b.example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,last_seen) VALUES
		('svc-a','target-a','https://shared.example.test',200,'Target A','2026-01-01 00:00:00'),
		('svc-b','target-b','https://shared.example.test/',200,'Target B','2026-01-02 00:00:00'),
		('svc-q','target-a','https://query.example.test?x=1',200,'Query','2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	// Repeat to verify idempotency.
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	var countA, countB int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='target-a'`).Scan(&countA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='target-b'`).Scan(&countB); err != nil {
		t.Fatal(err)
	}
	if countA != 2 || countB != 1 {
		t.Fatalf("row counts after normalization: target-a=%d (want 2), target-b=%d (want 1)", countA, countB)
	}

	var urlA, urlB, urlQ string
	if err := db.QueryRow(`SELECT url FROM http_services WHERE id='svc-a' AND target_id='target-a'`).Scan(&urlA); err != nil {
		t.Fatalf("target-a shared service missing: %v", err)
	}
	if err := db.QueryRow(`SELECT url FROM http_services WHERE id='svc-b' AND target_id='target-b'`).Scan(&urlB); err != nil {
		t.Fatalf("target-b shared service missing: %v", err)
	}
	if err := db.QueryRow(`SELECT url FROM http_services WHERE id='svc-q' AND target_id='target-a'`).Scan(&urlQ); err != nil {
		t.Fatalf("target-a query service missing: %v", err)
	}
	if urlA != "https://shared.example.test/" {
		t.Fatalf("target-a url = %q, want https://shared.example.test/", urlA)
	}
	if urlB != "https://shared.example.test/" {
		t.Fatalf("target-b url = %q, want https://shared.example.test/", urlB)
	}
	if urlQ != "https://query.example.test/?x=1" {
		t.Fatalf("query url = %q, want https://query.example.test/?x=1", urlQ)
	}
}

func TestMigrateTargetExclusionsSplitsManualAndBounty(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "exclusions-migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	legacy := "admin.example.test, 10.0.0.0/8\r\n#bounty:prog-1|*.staging.example.test (do not test)\n"
	if _, err := db.Exec(`INSERT INTO targets (id, domain, exclude_scope) VALUES ('t1', 'example.test', ?)`, legacy); err != nil {
		t.Fatal(err)
	}

	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	var remainingLegacy string
	if err := db.QueryRow(`SELECT COALESCE(exclude_scope, '') FROM targets WHERE id='t1'`).Scan(&remainingLegacy); err != nil {
		t.Fatal(err)
	}
	if remainingLegacy != "" {
		t.Fatalf("targets.exclude_scope after migration = %q, want empty", remainingLegacy)
	}

	type exclusionRow struct {
		source    string
		programID string
		pattern   string
	}
	readRows := func() []exclusionRow {
		t.Helper()
		rows, err := db.Query(`SELECT source, program_id, pattern FROM target_exclusions WHERE target_id='t1' ORDER BY source, program_id, pattern`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []exclusionRow
		for rows.Next() {
			var r exclusionRow
			if err := rows.Scan(&r.source, &r.programID, &r.pattern); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	want := []exclusionRow{
		{source: "bounty", programID: "prog-1", pattern: "*.staging.example.test (do not test)"},
		{source: "manual", programID: "", pattern: "10.0.0.0/8"},
		{source: "manual", programID: "", pattern: "admin.example.test"},
	}
	got := readRows()
	if len(got) != len(want) {
		t.Fatalf("migrated rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Repeat migration must be idempotent and never resurrect deleted rows.
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if got := readRows(); len(got) != len(want) {
		t.Fatalf("rows after repeat migration = %+v, want %+v", got, want)
	}
	if _, err := db.Exec(`DELETE FROM target_exclusions WHERE target_id='t1' AND pattern='admin.example.test'`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if got := readRows(); len(got) != len(want)-1 {
		t.Fatalf("deleted exclusion resurrected after repeat migration: got %+v", got)
	}
}
