package api

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetArtifactArchiveIncludesDatasetsAndJavaScript(t *testing.T) {
	h, adminID := newIsoHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES('artifact-target','example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO backup_findings(id,target_id,url,file_type,status_code,content_length)
		VALUES('backup','artifact-target','https://example.test/back/.env','env',200,42)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO js_files(id,target_id,url,size,hash,analyzed)
		VALUES('js','artifact-target','https://example.test/assets/chunk.123.js',21,'old-hash',1)`); err != nil {
		t.Fatal(err)
	}
	screenshotRoot := t.TempDir()
	screenshotPath := filepath.Join(screenshotRoot, "page.png")
	if err := os.WriteFile(screenshotPath, []byte("fake-png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO screenshots(id,target_id,url,file_path,width,height)
		VALUES('shot','artifact-target','https://example.test/',?,1280,720)`, screenshotPath); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "artifacts.zip")
	fetch := func(_ context.Context, scope, rawURL string) ([]byte, string, error) {
		if scope != "example.test" || rawURL != "https://example.test/assets/chunk.123.js" {
			t.Fatalf("unexpected fetch scope=%q url=%q", scope, rawURL)
		}
		return []byte(`window.reconner=true;`), rawURL, nil
	}
	if err := writeTargetArtifactArchive(context.Background(), h.db, dst, "artifact-target", "example.test", screenshotRoot, fetch); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entries := make(map[string][]byte)
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		if err != nil {
			rc.Close()
			t.Fatal(err)
		}
		rc.Close()
		entries[file.Name] = data
	}
	if !strings.Contains(string(entries["data/backup_findings.json"]), "/back/.env") {
		t.Fatalf("backup dataset missing nested .env: %s", entries["data/backup_findings.json"])
	}
	if !strings.Contains(string(entries["javascript/index.json"]), "chunk.123.js") {
		t.Fatalf("JavaScript index missing source URL: %s", entries["javascript/index.json"])
	}
	var manifest artifactManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.JavaScript.Included != 1 || manifest.JavaScript.Failed != 0 || manifest.DatasetCounts["backup_findings"] != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if manifest.Screenshots.Included != 1 || len(manifest.Screenshots.Files) != 1 || string(entries[manifest.Screenshots.Files[0].ArchivePath]) != "fake-png" {
		t.Fatalf("screenshot artifact missing: %+v", manifest.Screenshots)
	}
	var foundJS bool
	for name, body := range entries {
		if strings.HasPrefix(name, "javascript/") && name != "javascript/index.json" && string(body) == `window.reconner=true;` {
			foundJS = true
		}
	}
	if !foundJS {
		t.Fatal("archive did not include fetched JavaScript content")
	}
}

func TestTargetArtifactArchiveIncludesWatchScopeAndCSSDatasets(t *testing.T) {
	h, adminID := newIsoHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES('watch-target','watch.example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name)
		VALUES('prog-1','hackerone','ext-1','watch-prog','Watch Program')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO project_programs(target_id,program_id,auto_sync)
		VALUES('watch-target','prog-1',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO bounty_scope_events(id,target_id,program_id,event_type,identifier)
		VALUES('bse-1','watch-target','prog-1','added','api.watch.example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO watch_hosts(target_id,host,in_scope)
		VALUES('watch-target','app.watch.example.test',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO watch_scope_events(id,target_id,program_id,identifier,event_type)
		VALUES('wse-1','watch-target','prog-1','app.watch.example.test','landed')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO watch_round_changes(id,target_id,task_id,url,change_type,old_value,new_value)
		VALUES('wrc-1','watch-target','task-1','https://app.watch.example.test','http_status','404','200')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO http_observation_baselines(target_id,service_url,observation_type,status_code,title)
		VALUES('watch-target','https://app.watch.example.test','watch',200,'App')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO css_files(id,target_id,url,size,hash)
		VALUES('css-1','watch-target','https://app.watch.example.test/app.css',128,'abc123')`); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "watch-artifacts.zip")
	noopFetch := func(_ context.Context, _, rawURL string) ([]byte, string, error) {
		return nil, rawURL, nil
	}
	if err := writeTargetArtifactArchive(context.Background(), h.db, dst, "watch-target", "watch.example.test", t.TempDir(), noopFetch); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entries := make(map[string][]byte)
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name] = data
	}

	var manifest artifactManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"watch_round_changes":        "wrc-1",
		"watch_scope_events":         "wse-1",
		"watch_hosts":                "app.watch.example.test",
		"bounty_scope_events":        "bse-1",
		"http_observation_baselines": "https://app.watch.example.test",
		"css_files":                  "app.css",
		"project_programs":           "prog-1",
	}
	for table, needle := range want {
		if manifest.DatasetCounts[table] != 1 {
			t.Fatalf("dataset %s count = %d, want 1", table, manifest.DatasetCounts[table])
		}
		body, ok := entries["data/"+table+".json"]
		if !ok {
			t.Fatalf("missing data/%s.json in archive", table)
		}
		if !strings.Contains(string(body), needle) {
			t.Fatalf("data/%s.json missing %q: %s", table, needle, string(body))
		}
	}
}
