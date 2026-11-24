package scheduler

import "testing"

// A blocked preflight must not leave a watch project due in the past. The
// terminal rules advance the next round and count the failed attempt.
func TestFailTaskPreflightAdvancesWatchSchedule(t *testing.T) {
	s := newTestScheduler(t)
	_, err := s.db.Exec(`INSERT INTO targets (id, domain, kind, watch_only, watch_next_run, watch_paused, watch_fail_count)
		VALUES ('t1','example.test','web',1,'2020-01-01 00:00:00',0,0)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO tasks (id,target_id,type,status,modules,total,started_at)
		VALUES ('task-1','t1',?,'running','[]',0,CURRENT_TIMESTAMP)`, watchScanType)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO task_phases (task_id,phase_index,module,status) VALUES ('task-1',0,?,'pending')`, ModuleHTTPProbe)
	if err != nil {
		t.Fatal(err)
	}

	s.failTaskPreflight("task-1", "t1", "scope denied")

	var status string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task-1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("task status=%q, want failed", status)
	}
	var pending int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='task-1' AND status IN ('pending','running')`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("unresolved phases=%d, want 0", pending)
	}
	var fails int
	var next string
	if err := s.db.QueryRow(`SELECT COALESCE(watch_fail_count,0), COALESCE(watch_next_run,'') FROM targets WHERE id='t1'`).Scan(&fails, &next); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("watch_fail_count=%d, want 1", fails)
	}
	if next == "" || next <= "2020-01-01 00:00:00" {
		t.Fatalf("watch_next_run=%q, want a future time", next)
	}
}
