package scheduler

import (
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func insertRetentionTarget(t *testing.T, s *Scheduler, id string, paused bool) {
	t.Helper()
	next := "2026-01-01 00:00:00"
	p := 0
	if paused {
		p = 1
	}
	_, err := s.db.Exec(`INSERT INTO targets(id,domain,watch_only,watch_paused,watch_next_run) VALUES(?,?,1,?,?)`, id, id+".test", p, next)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPruneWatchKeepsLogsOfActiveTasks(t *testing.T) {
	s := newTestScheduler(t)
	insertRetentionTarget(t, s, "t1", false)
	old := time.Now().UTC().AddDate(0, 0, -200).Format("2006-01-02 15:04:05")
	for _, id := range []string{"active", "done"} {
		status := "running"
		if id == "done" {
			status = "finished"
		}
		_, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,priority,modules,total,created_at,finished_at)
			VALUES(?,?,'watch_scan',?,1,'[]',0,?,?)`, id, "t1", status, old, old)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.db.Exec(`INSERT INTO task_logs(task_id,message,created_at) VALUES(?,'log',?)`, id, old)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.db.Exec(`INSERT INTO task_phases(task_id,phase_index,module,status) VALUES(?,0,'http_probe','pending')`, id)
		if err != nil {
			t.Fatal(err)
		}
	}
	s.cfg = &config.Config{WatchRowsRetentionDays: 1, WatchScopeEventsRetentionDays: 1}
	s.pruneWatchGlobalHistory()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_logs WHERE task_id='active'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("active task logs=%d, want 1", count)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='active'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("active task phases=%d, want 1", count)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_logs WHERE task_id='done'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("finished task logs=%d, want 0", count)
	}
}

func TestPruneWatchKeepsRowsOfPausedTargets(t *testing.T) {
	s := newTestScheduler(t)
	insertRetentionTarget(t, s, "paused", true)
	old := time.Now().UTC().AddDate(0, 0, -200).Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(`INSERT INTO subdomains(id,target_id,subdomain,source,last_seen) VALUES('sd','paused','a.test','dns',?)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_services(id,target_id,url,source,last_seen) VALUES('hs','paused','https://a.test','probe',?)`, old); err != nil {
		t.Fatal(err)
	}
	s.cfg = &config.Config{WatchRowsRetentionDays: 1, WatchScopeEventsRetentionDays: 1}
	s.pruneWatchTargetRows()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id='paused'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("paused subdomains=%d, want 1", count)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id='paused'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("paused services=%d, want 1", count)
	}
}

func TestPruneWatchGlobalHistoryWithNoWatchOnlyTargets(t *testing.T) {
	s := newTestScheduler(t)
	insertRetentionTarget(t, s, "deep", false)
	if _, err := s.db.Exec(`UPDATE targets SET watch_only=0 WHERE id='deep'`); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().AddDate(0, 0, -100).Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,priority,modules,total,created_at,finished_at)
		VALUES('old','deep','watch_scan','finished',1,'[]',0,?,?)`, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO task_logs(task_id,message,created_at) VALUES('old','done',?)`, old); err != nil {
		t.Fatal(err)
	}
	s.cfg = &config.Config{WatchRowsRetentionDays: 1, WatchScopeEventsRetentionDays: 1}
	s.pruneWatchGlobalHistory()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE id='old'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old finished task remained: %d", count)
	}
}

func TestPruneOrphanObservationBaselines(t *testing.T) {
	s := newTestScheduler(t)
	insertRetentionTarget(t, s, "t1", false)
	old := time.Now().UTC().AddDate(0, 0, -200).Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(`INSERT INTO http_observation_baselines(target_id,service_url,observation_type,status_code,detected_at)
		VALUES('t1','https://gone.test/','deep_http',200,?)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_observation_baselines(target_id,service_url,observation_type,status_code,detected_at)
		VALUES('t1','https://live.test/','deep_http',200,?)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_services(id,target_id,url,source,last_seen) VALUES('hs','t1','https://live.test/','seed',?)`, old); err != nil {
		t.Fatal(err)
	}
	s.cfg = &config.Config{WatchRowsRetentionDays: 1, WatchScopeEventsRetentionDays: 1}
	s.pruneWatchTargetRows()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM http_observation_baselines`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("baselines=%d, want 1 (seed service must keep its baseline)", count)
	}
}
