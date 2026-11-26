package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

func TestVerifyReplayNetworkErrorPreservesConfirmedFinding(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// Seed a confirmed LFI finding (replayable class) and an operator-triaged finding.
	if _, err := db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority, status, lifecycle, triage)
		VALUES
			('vf-net-err', ?, 'lfi', 'high', 'https://example.test/download?file=x', 'file', '../../etc/passwd', 'root:x:0:0:', 95, 76, 'finding', 'LEGACY', ''),
			('vf-triage-confirmed', ?, 'lfi', 'high', 'https://example.test/other?file=x', 'file', '../../etc/passwd', 'root:x:0:0:', 95, 76, 'finding', 'REJECTED', 'confirmed')
	`, tid, tid); err != nil {
		t.Fatalf("seed vuln_findings: %v", err)
	}
	if _, err := db.Exec(`UPDATE vuln_findings SET candidate_id='cand-rej' WHERE id='vf-triage-confirmed'`); err != nil {
		t.Fatalf("set candidate_id: %v", err)
	}

	origClient := verifyClient
	verifyClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("simulated transient dial timeout")
		}),
	}
	t.Cleanup(func() { verifyClient = origClient })

	vs := NewVerifyScanner(db, nil, &config.Config{EnableSQLmap: false, NucleiVerify: false}, logger.New("error"), nil)
	if err := vs.Run(context.Background(), tid, func(string, string, string) {}); err != nil {
		t.Fatalf("VerifyScanner.Run: %v", err)
	}

	var status string
	var conf int
	if err := db.QueryRow(`SELECT status, confidence FROM vuln_findings WHERE id='vf-net-err'`).Scan(&status, &conf); err != nil {
		t.Fatalf("query vf-net-err: %v", err)
	}
	if status != StatusFinding || conf != 95 {
		t.Fatalf("transient replay error downgraded finding: status=%q conf=%d, want status=%q conf=95", status, conf, StatusFinding)
	}

	if err := db.QueryRow(`SELECT status, confidence FROM vuln_findings WHERE id='vf-triage-confirmed'`).Scan(&status, &conf); err != nil {
		t.Fatalf("query vf-triage-confirmed: %v", err)
	}
	if status != StatusFinding || conf != 95 {
		t.Fatalf("operator-confirmed finding was overwritten: status=%q conf=%d, want status=%q conf=95", status, conf, StatusFinding)
	}
}

func TestAnalyzeJSContentSyncsHashAndBodyAndRotatesOld(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	js := NewJSScanner(db, nil, &config.Config{}, logger.New("error"), nil)
	const jsURL = "https://example.test/static/app.js"

	v1 := []byte("console.log('version-1');")
	if err := js.analyzeJSContent(context.Background(), tid, jsURL, v1, nil); err != nil {
		t.Fatalf("analyzeJSContent v1: %v", err)
	}

	var hash1, body1, oldHash1, oldBody1 string
	if err := db.QueryRow(`SELECT hash, body, old_hash, old_body FROM js_files WHERE target_id=? AND url=?`, tid, jsURL).
		Scan(&hash1, &body1, &oldHash1, &oldBody1); err != nil {
		t.Fatalf("query v1: %v", err)
	}
	if body1 != string(v1) || hash1 == "" || oldHash1 != "" || oldBody1 != "" {
		t.Fatalf("v1 row mismatch: hash=%q body=%q old_hash=%q old_body=%q", hash1, body1, oldHash1, oldBody1)
	}

	// Update with content exceeding 256 KiB cap to verify rotation + truncation.
	v2 := []byte("console.log('version-2');" + strings.Repeat("A", monitorBodyCaptureCap+1024))
	if err := js.analyzeJSContent(context.Background(), tid, jsURL, v2, nil); err != nil {
		t.Fatalf("analyzeJSContent v2: %v", err)
	}

	var hash2, body2, oldHash2, oldBody2 string
	var size2 int
	if err := db.QueryRow(`SELECT size, hash, body, old_hash, old_body FROM js_files WHERE target_id=? AND url=?`, tid, jsURL).
		Scan(&size2, &hash2, &body2, &oldHash2, &oldBody2); err != nil {
		t.Fatalf("query v2: %v", err)
	}
	if size2 != len(v2) {
		t.Fatalf("size = %d, want %d", size2, len(v2))
	}
	if len(body2) != monitorBodyCaptureCap {
		t.Fatalf("len(body2) = %d, want cap %d", len(body2), monitorBodyCaptureCap)
	}
	if hash2 == hash1 {
		t.Fatalf("expected hash to update on content change")
	}
	if oldHash2 != hash1 || oldBody2 != string(v1) {
		t.Fatalf("old snapshot not rotated: old_hash=%q (want %q), old_body=%q (want %q)", oldHash2, hash1, oldBody2, string(v1))
	}
}

func TestVerifySecretsTriStateHandling(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	const jsFileID = "jsf-1"
	const jsURL = "https://example.test/assets/bundle.js"
	if _, err := db.Exec(`INSERT INTO js_files (id, target_id, url, size, hash, body, analyzed) VALUES (?, ?, ?, 10, 'abc', 'x', 1)`, jsFileID, tid, jsURL); err != nil {
		t.Fatalf("seed js_files: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO js_findings (id, target_id, js_file_id, type, value, severity, verified)
		VALUES
			('jf-429', ?, ?, 'github_token', 'ghp_rate_limited_token', 'high', 0),
			('jf-500', ?, ?, 'stripe_key', 'sk_live_server_error_token', 'critical', 0),
			('jf-401', ?, ?, 'sendgrid', 'SG.invalid_auth_token_123456', 'high', 0),
			('jf-ok',  ?, ?, 'slack_token', 'xoxb-valid-live-token-12345', 'high', 0)
	`, tid, jsFileID, tid, jsFileID, tid, jsFileID, tid, jsFileID); err != nil {
		t.Fatalf("seed js_findings: %v", err)
	}

	origClient := secretHTTPClient
	secretHTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case strings.Contains(req.URL.Host, "api.github.com"):
				return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("rate limit"))}, nil
			case strings.Contains(req.URL.Host, "api.stripe.com"):
				return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("upstream error"))}, nil
			case strings.Contains(req.URL.Host, "api.sendgrid.com"):
				return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("unauthorized"))}, nil
			case strings.Contains(req.URL.Host, "slack.com"):
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"team":"acme"}`))}, nil
			default:
				return nil, errors.New("unexpected provider host: " + req.URL.Host)
			}
		}),
	}
	t.Cleanup(func() { secretHTTPClient = origClient })

	var broadcasts []map[string]any
	js := NewJSScanner(db, nil, &config.Config{VerifySecrets: true}, logger.New("error"), func(event string, data any) {
		if event == "new_vuln_finding" {
			if m, ok := data.(map[string]any); ok {
				broadcasts = append(broadcasts, m)
			}
		}
	})

	js.verifySecrets(context.Background(), tid, func(string, string, string) {})

	checkJSFinding := func(id, wantSev string, wantVerified int) {
		t.Helper()
		var sev string
		var ver int
		if err := db.QueryRow(`SELECT severity, verified FROM js_findings WHERE id=?`, id).Scan(&sev, &ver); err != nil {
			t.Fatalf("query %s: %v", id, err)
		}
		if sev != wantSev || ver != wantVerified {
			t.Fatalf("%s: severity=%q verified=%d, want severity=%q verified=%d", id, sev, ver, wantSev, wantVerified)
		}
	}

	checkJSFinding("jf-429", "high", 0)
	checkJSFinding("jf-500", "critical", 0)
	checkJSFinding("jf-401", "info", 0)
	checkJSFinding("jf-ok", "critical", 1)

	var vfID, vfURL, vfStatus string
	if err := db.QueryRow(`SELECT id, url, status FROM vuln_findings WHERE target_id=? AND type='verified_secret_slack_token'`, tid).
		Scan(&vfID, &vfURL, &vfStatus); err != nil {
		t.Fatalf("expected verified secret projection in vuln_findings: %v", err)
	}
	if vfURL != jsURL || vfStatus != StatusFinding {
		t.Fatalf("vuln_findings projection mismatch: url=%q status=%q, want url=%q status=%q", vfURL, vfStatus, jsURL, StatusFinding)
	}
	if len(broadcasts) != 1 || broadcasts[0]["url"] != jsURL || broadcasts[0]["finding_id"] != vfID {
		t.Fatalf("broadcast mismatch: got %+v, want url=%q finding_id=%q", broadcasts, jsURL, vfID)
	}
}

func TestOpenRedirectVerifiedSurvivesCandidateOverwrite(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	const targetURL = "https://example.test/login"
	if err := upsertOpenRedirectFinding(db, "or-1", tid, targetURL,
		"https://example.test/login?next=https://evil.test -> https://evil.test",
		"next", 1, StatusFinding, "302 -> https://evil.test"); err != nil {
		t.Fatalf("insert verified open redirect: %v", err)
	}

	// A later candidate (unverified) probe for another parameter on the same URL must NOT clobber the verified finding.
	if err := upsertOpenRedirectFinding(db, "or-2", tid, targetURL,
		"https://example.test/login?return=/home -> /home",
		"return", 0, StatusCandidate, "302 -> /home"); err != nil {
		t.Fatalf("upsert candidate open redirect: %v", err)
	}

	var param, redirectTo, provenance, status string
	var verified int
	if err := db.QueryRow(`SELECT parameter, redirect_to, provenance, verified, status FROM open_redirect_findings WHERE target_id=? AND url=?`, tid, targetURL).
		Scan(&param, &redirectTo, &provenance, &verified, &status); err != nil {
		t.Fatalf("query open_redirect_findings: %v", err)
	}
	if verified != 1 || status != StatusFinding || param != "next" || !strings.Contains(redirectTo, "evil.test") || provenance != "302 -> https://evil.test" {
		t.Fatalf("verified open redirect clobbered: verified=%d status=%q param=%q redirect_to=%q provenance=%q",
			verified, status, param, redirectTo, provenance)
	}
}

func TestOperatorTriagedFindingSurvivesCandidateRejection(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	for _, triage := range []string{"confirmed", "accepted_risk", "fixed"} {
		t.Run(triage, func(t *testing.T) {
			urlStr := "https://example.test/item?t=" + triage
			candID, err := RecordCandidateResult(context.Background(), db, VulnerabilityCandidate{
				TargetID: tid, Type: "xss", Subtype: "reflected", URL: urlStr,
				Method: "GET", Parameter: "t", Location: "query", DetectionSource: "test",
				DetectionMethod: "browser", Severity: "high", Payload: "<svg onload=alert(1)>",
			}, VerifyResult{
				Verdict: VerifyVerified, Confidence: 99, Evidence: "proof", Method: "browser",
			}, FindingMeta{Actor: "test"})
			if err != nil {
				t.Fatalf("record confirmed finding: %v", err)
			}

			if _, err := db.Exec(`UPDATE vuln_findings SET triage=? WHERE candidate_id=?`, triage, candID); err != nil {
				t.Fatalf("set triage=%s: %v", triage, err)
			}

			if err := upsertFindingProjection(context.Background(), db, candID, VulnerabilityCandidate{
				TargetID: tid, Type: "xss", URL: urlStr, Parameter: "t",
			}, VerifyResult{Verdict: VerifyRejected, Reason: "auto-reject"}, CandRejected, FindingMeta{Actor: "verifier"}); err != nil {
				t.Fatalf("upsertFindingProjection CandRejected: %v", err)
			}

			var status string
			var conf int
			if err := db.QueryRow(`SELECT status, confidence FROM vuln_findings WHERE candidate_id=?`, candID).Scan(&status, &conf); err != nil {
				t.Fatalf("query vuln_findings: %v", err)
			}
			if status != StatusFinding || conf == 0 {
				t.Fatalf("triage=%q finding was rejected: status=%q conf=%d", triage, status, conf)
			}
		})
	}

	// Untriaged finding must still be rejected normally.
	candID, err := RecordCandidateResult(context.Background(), db, VulnerabilityCandidate{
		TargetID: tid, Type: "xss", Subtype: "reflected", URL: "https://example.test/untriaged?q=1",
		Method: "GET", Parameter: "q", Location: "query", DetectionSource: "test",
		DetectionMethod: "browser", Severity: "high", Payload: "<svg onload=alert(1)>",
	}, VerifyResult{
		Verdict: VerifyVerified, Confidence: 99, Evidence: "proof", Method: "browser",
	}, FindingMeta{Actor: "test"})
	if err != nil {
		t.Fatalf("record untriaged finding: %v", err)
	}
	if err := upsertFindingProjection(context.Background(), db, candID, VulnerabilityCandidate{
		TargetID: tid, Type: "xss", URL: "https://example.test/untriaged?q=1", Parameter: "q",
	}, VerifyResult{Verdict: VerifyRejected, Reason: "auto-reject"}, CandRejected, FindingMeta{Actor: "verifier"}); err != nil {
		t.Fatalf("reject untriaged: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM vuln_findings WHERE candidate_id=?`, candID).Scan(&status); err != nil {
		t.Fatalf("query untriaged: %v", err)
	}
	if status != "rejected" {
		t.Fatalf("untriaged finding status=%q, want rejected", status)
	}
}
