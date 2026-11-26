package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// The global Findings page (GET /findings) is the top-level "what did Reconner
// actually find" view. It must carry the reproduction payload alongside the
// evidence text -- otherwise a reviewer has no way to replay a finding from
// that page without opening the per-target detail view first.
func TestHandleListAllFindingsIncludesPayload(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "all-findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error")}

	if _, err := db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, status)
		VALUES ('f1','t1','sqli','high','https://example.test/?id=1','id',?,'DB error triggered by boundary','finding')`,
		"1' AND (1=1)-- -"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleListAllFindings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []allFinding `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Data))
	}
	if resp.Data[0].Payload != "1' AND (1=1)-- -" {
		t.Fatalf("expected the finding's reproduction payload to be included, got %q", resp.Data[0].Payload)
	}
}

func TestHandleListAllFindingsUnionsAllStoresFiltersAndPaginates(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "all-findings-union.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	member, err := a.CreateUser("analyst", "supersecret", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error")}

	if _, err := db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','alpha.example.test',?), ('t2','beta.example.test',?)`, adminID, member.ID); err != nil {
		t.Fatal(err)
	}
	// 1. vuln_findings: confirmed finding, candidate, false positive (excluded), and member target finding.
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority, status, triage, created_at) VALUES
		('vf-1','t1','sqli','critical','https://alpha.example.test/search?id=1','id','1 OR 1=1','sql error',95,400,'finding','','2026-01-05 00:00:00'),
		('vf-cand','t1','xss','medium','https://alpha.example.test/q','q','<svg>','reflected',50,100,'candidate','','2026-01-04 00:00:00'),
		('vf-fp','t1','sqli','high','https://alpha.example.test/fp','fp','x','fp',90,300,'finding','false_positive','2026-01-05 00:00:00'),
		('vf-member','t2','idor','high','https://beta.example.test/api/user','user_id','2','cross-tenant',90,200,'finding','','2026-01-03 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	// 2. nuclei_findings: verified (included) and rejected (excluded).
	if _, err := db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, severity, matched_url, description, curl_command, verification, confidence, created_at) VALUES
		('nf-1','t1','cve-2025-0001','critical','https://alpha.example.test/admin','RCE template','curl https://alpha.example.test/admin','verified',98,'2026-01-04 12:00:00'),
		('nf-rej','t1','cve-2025-0002','high','https://alpha.example.test/rej','rejected','curl x','rejected',0,'2026-01-04 11:00:00')`); err != nil {
		t.Fatal(err)
	}
	// 3. backup_findings.
	if _, err := db.Exec(`INSERT INTO backup_findings (id, target_id, url, file_type, status_code, content_length, created_at) VALUES
		('bf-1','t1','https://alpha.example.test/.env.bak','env',200,128,'2026-01-04 10:00:00')`); err != nil {
		t.Fatal(err)
	}
	// 4. open_redirect_findings: verified finding, candidate, and unverified non-candidate (excluded).
	if _, err := db.Exec(`INSERT INTO open_redirect_findings (id, target_id, url, redirect_to, parameter, verified, status, provenance, created_at) VALUES
		('or-1','t1','https://alpha.example.test/login?next=/','https://evil.test','next',1,'finding','302 Location','2026-01-04 09:00:00'),
		('or-cand','t1','https://alpha.example.test/out?r=/','https://evil.test','r',0,'candidate','meta refresh','2026-01-04 08:00:00'),
		('or-unv','t1','https://alpha.example.test/unv','https://evil.test','u',0,'finding','weak','2026-01-04 07:00:00')`); err != nil {
		t.Fatal(err)
	}
	// 5. js_files + js_findings: verified (included) and unverified (excluded).
	if _, err := db.Exec(`INSERT INTO js_files (id, target_id, url) VALUES ('jsf-1','t1','https://alpha.example.test/app.js')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO js_findings (id, target_id, js_file_id, type, value, context, severity, verified, created_at) VALUES
		('js-1','t1','jsf-1','aws_access_key','AKIAIOSFODNN7EXAMPLE','const key = ...','high',1,'2026-01-04 06:00:00'),
		('js-unv','t1','jsf-1','generic_secret','secret','ctx','low',0,'2026-01-04 05:00:00')`); err != nil {
		t.Fatal(err)
	}

	type listResp struct {
		Success bool         `json:"success"`
		Data    []allFinding `json:"data"`
		Total   int          `json:"total"`
		Page    int          `json:"page"`
		Limit   int          `json:"limit"`
	}
	fetch := func(uid int64, rawURL string) listResp {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, uid))
		rec := httptest.NewRecorder()
		h.handleListAllFindings(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", rawURL, rec.Code, rec.Body.String())
		}
		var resp listResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v body=%s", rawURL, err, rec.Body.String())
		}
		if !resp.Success {
			t.Fatalf("%s expected success=true", rawURL)
		}
		return resp
	}

	// Default status=finding for admin includes all 5 stores across both targets (6 rows).
	all := fetch(adminID, "/api/findings")
	if all.Total != 6 || len(all.Data) != 6 || all.Page != 1 || all.Limit != 200 {
		t.Fatalf("default admin findings = total:%d len:%d page:%d limit:%d", all.Total, len(all.Data), all.Page, all.Limit)
	}
	byID := map[string]allFinding{}
	for _, f := range all.Data {
		byID[f.ID] = f
	}
	checks := []struct {
		id, source, sourceTab, url string
	}{
		{"vf-1", "native", "vulns", "https://alpha.example.test/search?id=1"},
		{"nf-1", "nuclei", "nuclei", "https://alpha.example.test/admin"},
		{"bf-1", "backup", "backups", "https://alpha.example.test/.env.bak"},
		{"or-1", "open_redirect", "redirects", "https://alpha.example.test/login?next=/"},
		{"js-1", "js_secret", "js-findings", "https://alpha.example.test/app.js"},
		{"vf-member", "native", "vulns", "https://beta.example.test/api/user"},
	}
	for _, c := range checks {
		f, ok := byID[c.id]
		if !ok {
			t.Fatalf("missing finding %s in unified response", c.id)
		}
		if f.Source != c.source || f.SourceTab != c.sourceTab || f.URL != c.url {
			t.Fatalf("finding %s = source:%q tab:%q url:%q want %q/%q/%q",
				c.id, f.Source, f.SourceTab, f.URL, c.source, c.sourceTab, c.url)
		}
	}

	// Candidates mode returns vuln_findings candidates + open_redirect candidates only.
	cands := fetch(adminID, "/api/findings?status=candidate")
	if cands.Total != 2 || len(cands.Data) != 2 {
		t.Fatalf("candidates = total:%d len:%d", cands.Total, len(cands.Data))
	}
	candTabs := map[string]string{}
	for _, f := range cands.Data {
		candTabs[f.ID] = f.SourceTab
	}
	if candTabs["vf-cand"] != "candidates" || candTabs["or-cand"] != "redirects" {
		t.Fatalf("unexpected candidate tabs: %+v", candTabs)
	}

	// Owner scoping: member sees only their own target's findings.
	memberResp := fetch(member.ID, "/api/findings")
	if memberResp.Total != 1 || len(memberResp.Data) != 1 || memberResp.Data[0].ID != "vf-member" {
		t.Fatalf("member isolation broken: %+v", memberResp)
	}

	// source, target_id, and q filters.
	bySource := fetch(adminID, "/api/findings?source=js_secret")
	if bySource.Total != 1 || len(bySource.Data) != 1 || bySource.Data[0].ID != "js-1" {
		t.Fatalf("source=js_secret filter = %+v", bySource)
	}
	byTarget := fetch(adminID, "/api/findings?target_id=t2")
	if byTarget.Total != 1 || len(byTarget.Data) != 1 || byTarget.Data[0].ID != "vf-member" {
		t.Fatalf("target_id=t2 filter = %+v", byTarget)
	}
	byQParam := fetch(adminID, "/api/findings?q=next")
	if byQParam.Total != 1 || len(byQParam.Data) != 1 || byQParam.Data[0].ID != "or-1" {
		t.Fatalf("q=next filter = %+v", byQParam)
	}
	byQType := fetch(adminID, "/api/findings?q=cve-2025")
	if byQType.Total != 1 || len(byQType.Data) != 1 || byQType.Data[0].ID != "nf-1" {
		t.Fatalf("q=cve-2025 filter = %+v", byQType)
	}
	byQDomain := fetch(adminID, "/api/findings?q=beta.example")
	if byQDomain.Total != 1 || len(byQDomain.Data) != 1 || byQDomain.Data[0].ID != "vf-member" {
		t.Fatalf("q=beta.example filter = %+v", byQDomain)
	}

	// Pagination returns consistent total and disjoint slices.
	p1 := fetch(adminID, "/api/findings?page=1&limit=2")
	p2 := fetch(adminID, "/api/findings?page=2&limit=2")
	p3 := fetch(adminID, "/api/findings?page=3&limit=2")
	if p1.Total != 6 || p2.Total != 6 || p3.Total != 6 || len(p1.Data) != 2 || len(p2.Data) != 2 || len(p3.Data) != 2 {
		t.Fatalf("pagination mismatch: p1=%d/%d p2=%d/%d p3=%d/%d",
			len(p1.Data), p1.Total, len(p2.Data), p2.Total, len(p3.Data), p3.Total)
	}
	seen := map[string]bool{}
	for _, page := range [][]allFinding{p1.Data, p2.Data, p3.Data} {
		for _, f := range page {
			if seen[f.ID] {
				t.Fatalf("duplicate finding %s across pages", f.ID)
			}
			seen[f.ID] = true
		}
	}
	if len(seen) != 6 {
		t.Fatalf("expected 6 distinct findings across 3 pages, got %d", len(seen))
	}
}

func TestHandleListAllFindingsSeverityOrderDedupNucleiAndOffset(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "all-findings-order-dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error")}

	if _, err := db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','order.example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}

	type listResp struct {
		Success bool         `json:"success"`
		Data    []allFinding `json:"data"`
		Total   int          `json:"total"`
		Page    int          `json:"page"`
		Limit   int          `json:"limit"`
	}
	fetch := func(rawURL string) listResp {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
		rec := httptest.NewRecorder()
		h.handleListAllFindings(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", rawURL, rec.Code, rec.Body.String())
		}
		var resp listResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s: %v body=%s", rawURL, err, rec.Body.String())
		}
		return resp
	}

	// Seed rows covering:
	// - Severity-first ordering: critical nuclei and critical js_secret must sort ahead of high/low native with priority=200.
	// - Nuclei verification: 'unverified' included, 'rejected' excluded.
	// - Dedup across nuclei, backup, and js_findings when projected into vuln_findings.
	if _, err := db.Exec(`INSERT INTO js_files (id, target_id, url) VALUES ('jsf-1','t1','https://order.example.test/bundle.js')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority, status, triage, created_at) VALUES
		('vf-high','t1','sqli','high','https://order.example.test/high','id','1','err',95,200,'finding','','2026-02-10 00:00:00'),
		('vf-low','t1','info_leak','low','https://order.example.test/low','p','x','err',90,200,'finding','','2026-02-11 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, severity, matched_url, description, curl_command, verification, confidence, created_at) VALUES
		('nf-unv-cve','t1','cve-2026-1000','critical','https://order.example.test/cve','unverified CVE','curl x','unverified',90,'2026-02-01 00:00:00'),
		('nf-rejected','t1','cve-2026-1001','critical','https://order.example.test/rej','rejected CVE','curl x','rejected',90,'2026-02-02 00:00:00'),
		('nf-projected','t1','cve-2026-1002','high','https://order.example.test/proj-nuclei','projected CVE','curl x','verified',95,'2026-02-03 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO js_findings (id, target_id, js_file_id, type, value, context, severity, verified, created_at) VALUES
		('js-crit','t1','jsf-1','stripe_live_key','sk_live_123','ctx','critical',1,'2026-02-05 00:00:00'),
		('js-projected','t1','jsf-1','aws_access_key','AKIA123','ctx','high',1,'2026-02-04 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO backup_findings (id, target_id, url, file_type, status_code, content_length, created_at) VALUES
		('bf-projected','t1','https://order.example.test/db.sql.bak','sql',200,512,'2026-02-03 00:00:00')`); err != nil {
		t.Fatal(err)
	}

	// Project nf-projected (via candidate.source_result_id), bf-projected (type='exposed_backup' + url),
	// and js-projected (provenance='js_findings:'||id) into vuln_findings.
	if _, err := db.Exec(`INSERT INTO candidates (id, target_id, type, url, fingerprint, source_result_id) VALUES
		('cand-nf','t1','nuclei_cve','https://order.example.test/proj-nuclei','fp-nf','nf-projected')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, status, triage, candidate_id, provenance, priority, created_at) VALUES
		('vf-proj-nf','t1','nuclei_cve','high','https://order.example.test/proj-nuclei','','finding','','cand-nf','',100,'2026-02-03 00:00:00'),
		('vf-proj-bf','t1','exposed_backup','high','https://order.example.test/db.sql.bak','','finding','','','',90,'2026-02-03 00:00:00'),
		('vf-proj-js','t1','aws_access_key','high','https://order.example.test/bundle.js','aws_access_key:js-projected','finding','','','js_findings:js-projected',80,'2026-02-04 00:00:00')`); err != nil {
		t.Fatal(err)
	}

	resp := fetch("/api/findings")
	// Expected 7 rows: js-crit, nf-unv-cve (critical); vf-high, vf-proj-nf, vf-proj-bf, vf-proj-js (high); vf-low (low).
	// Excluded: nf-rejected (rejected), nf-projected / bf-projected / js-projected (deduped against vuln_findings).
	wantOrder := []string{"js-crit", "nf-unv-cve", "vf-high", "vf-proj-nf", "vf-proj-bf", "vf-proj-js", "vf-low"}
	if resp.Total != len(wantOrder) || len(resp.Data) != len(wantOrder) {
		gotIDs := make([]string, len(resp.Data))
		for i, f := range resp.Data {
			gotIDs[i] = f.ID + "(" + f.Source + ":" + f.Severity + ")"
		}
		t.Fatalf("total=%d got=%v, want %v", resp.Total, gotIDs, wantOrder)
	}
	for i, wantID := range wantOrder {
		if resp.Data[i].ID != wantID {
			gotIDs := make([]string, len(resp.Data))
			for j, f := range resp.Data {
				gotIDs[j] = f.ID
			}
			t.Fatalf("order mismatch at %d: got %v, want %v", i, gotIDs, wantOrder)
		}
	}

	// Explicit offset overrides page offset cleanly (page=1&limit=2&offset=3 -> items [3:5]).
	offResp := fetch("/api/findings?page=1&limit=2&offset=3")
	if offResp.Total != len(wantOrder) || len(offResp.Data) != 2 || offResp.Data[0].ID != "vf-proj-nf" || offResp.Data[1].ID != "vf-proj-bf" {
		t.Fatalf("offset=3 limit=2 got %+v, want [vf-proj-nf, vf-proj-bf]", offResp.Data)
	}
	// Explicit offset=0 overrides page=3.
	offZero := fetch("/api/findings?page=3&limit=2&offset=0")
	if len(offZero.Data) != 2 || offZero.Data[0].ID != "js-crit" || offZero.Data[1].ID != "nf-unv-cve" {
		t.Fatalf("offset=0 with page=3 got %+v, want [js-crit, nf-unv-cve]", offZero.Data)
	}

	// Marking projected vuln_findings rows as false_positive suppresses BOTH the native row AND the secondary table row.
	if _, err := db.Exec(`UPDATE vuln_findings SET triage='false_positive' WHERE id IN ('vf-proj-nf','vf-proj-bf','vf-proj-js')`); err != nil {
		t.Fatal(err)
	}
	afterFP := fetch("/api/findings")
	wantAfterFP := []string{"js-crit", "nf-unv-cve", "vf-high", "vf-low"}
	if afterFP.Total != len(wantAfterFP) || len(afterFP.Data) != len(wantAfterFP) {
		gotIDs := make([]string, len(afterFP.Data))
		for i, f := range afterFP.Data {
			gotIDs[i] = f.ID
		}
		t.Fatalf("after false_positive: total=%d got=%v, want %v", afterFP.Total, gotIDs, wantAfterFP)
	}
	for i, wantID := range wantAfterFP {
		if afterFP.Data[i].ID != wantID {
			t.Fatalf("after false_positive mismatch at %d: got %s, want %s", i, afterFP.Data[i].ID, wantID)
		}
	}
}
