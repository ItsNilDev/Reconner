package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// TestWatchHTTPProbeFailsWhenHttpxUnavailable proves that a breadth round treats
// a missing probe tool as a phase failure instead of a healthy empty round. The
// liveness ledger must not be damaged by a tool outage.
func TestWatchHTTPProbeFailsWhenHttpxUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	db, err := database.New(filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, host); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO subdomains (id, target_id, subdomain, source, last_seen) VALUES (?,?,?, 'seed', CURRENT_TIMESTAMP)`,
		uuid.New().String(), tid, host); err != nil {
		t.Fatal(err)
	}

	exec := tools.NewToolFreeExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	s := NewHTTPScanner(db, exec, &config.Config{}, logger.New("error"))
	ctx := WithWatchMode(context.Background(), true)

	if err := s.Run(ctx, tid, func(_, _, _ string) {}); err == nil {
		t.Fatal("watch probe with no httpx must fail the phase, not return nil")
	}
	var misses int
	if err := db.QueryRow(
		`SELECT COALESCE(alive_misses,0) FROM subdomains WHERE target_id=? AND subdomain=?`, tid, host).Scan(&misses); err != nil {
		t.Fatal(err)
	}
	if misses != 0 {
		t.Fatalf("failed tool damaged liveness ledger: alive_misses=%d, want 0", misses)
	}
}

// TestHTTPProbeFallsBackWhenHttpxUnavailable proves the resilience gate: when
// httpx cannot run (here: a tool-free executor, the same observable state as the
// aparat.com "exit status 2" — httpx present but yielding zero services), the
// native prober still populates http_services so the rest of the scan has input
// instead of collapsing to "No HTTP services found" everywhere.
func TestHTTPProbeFallsBackWhenHttpxUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-origin")
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Live</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String() // 127.0.0.1:port

	db, err := database.New(filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, host); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO subdomains (id, target_id, subdomain, source, last_seen) VALUES (?,?,?, 'seed', CURRENT_TIMESTAMP)`,
		uuid.New().String(), tid, host); err != nil {
		t.Fatal(err)
	}

	// Tool-free executor => httpx is unavailable, so Run must take the fallback path.
	exec := tools.NewToolFreeExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	s := NewHTTPScanner(db, exec, &config.Config{}, logger.New("error"))

	if err := s.Run(context.Background(), tid, func(_, _, _ string) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM http_services WHERE target_id=? AND status_code=200`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("fallback prober stored no live HTTP service — a failed httpx would collapse the whole scan")
	}
}
