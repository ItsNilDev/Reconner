package scheduler

import (
	"context"
	"testing"

	"github.com/recon-platform/internal/models"
)

// A resume must keep the per-asset scope and the scan-option tokens. It must
// not re-add a module the operator already completed.
func TestResumeTaskPreservesScopeAndOptions(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,kind) VALUES ('resume-target','app.example.test','web')`); err != nil {
		t.Fatal(err)
	}
	original, err := s.createTaskWithOptions("resume-target",
		[]string{ModuleHTTPProbe, ModuleXSS, "speed_slow", "single_endpoint"},
		1, ModuleXSS, "app.example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE tasks SET status='failed', completed_modules=? WHERE id=?`,
		models.StringSliceToJSON([]string{ModuleHTTPProbe}), original.ID); err != nil {
		t.Fatal(err)
	}

	resumed, err := s.ResumeTask(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	var scope string
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COALESCE(scope_override,'') FROM tasks WHERE id=?`, resumed.ID).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != "app.example.test" {
		t.Fatalf("scope_override=%q, want app.example.test", scope)
	}
	for _, token := range []string{"speed_slow", "single_endpoint", ModuleXSS} {
		if !containsModule(resumed.Modules, token) {
			t.Errorf("resumed modules=%v, missing %q", resumed.Modules, token)
		}
	}
	if containsModule(resumed.Modules, ModuleHTTPProbe) {
		t.Fatalf("resume re-added completed module http_probe: %v", resumed.Modules)
	}
}
