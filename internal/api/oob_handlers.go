package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattn/go-sqlite3"
	"github.com/recon-platform/internal/scanner"
)

// handleOOBCallback records an out-of-band interaction proving blind SSRF or
// blind RCE: the TARGET SERVER (not a browser) fetched /oob/<token> because our
// injected payload made it. Public, no auth. Any HTTP method — SSRF/RCE fetches
// can be GET/HEAD/POST — so this is registered without a method filter.
func (h *Handler) handleOOBCallback(w http.ResponseWriter, r *http.Request) {
	token := sanitizeToken(mux.Vars(r)["token"])
	if token == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	h.RecordOOBHit(token, clientIP(r), r.Method, truncateStr(r.UserAgent(), 200), "/oob/"+token)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

// oobVulnType maps an oob_probe kind to the finding type it proves.
func oobVulnType(kind string) string {
	switch kind {
	case "rce":
		return "blind_rce"
	case "xxe":
		return "blind_xxe"
	case "sqli":
		return "blind_sqli"
	case "ssti":
		return "blind_ssti"
	case "log4shell":
		return "log4shell_rce"
	case "deserialization":
		return "insecure_deserialization"
	case "file_upload_ssrf", "file_upload_xxe":
		return "file_upload"
	case "wordpress_pingback":
		return "wordpress_xmlrpc_pingback"
	}
	return "blind_ssrf"
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	var se sqlite3.Error
	if errors.As(err, &se) && (se.Code == sqlite3.ErrBusy || se.Code == sqlite3.ErrLocked) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "busy")
}

// RecordOOBHit correlates an out-of-band callback (HTTP /oob/<token> OR the raw
// JNDI/LDAP listener for Log4Shell) back to its injection point and promotes it
// to a confirmed critical finding. Idempotent per token; emits the alert only on
// the first hit. `via` describes how the callback arrived (e.g. "/oob/<token>"
// or "JNDI/LDAP :1389"). Returns true if the token was known.
func (h *Handler) RecordOOBHit(token, srcIP, method, ua, via string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var targetID, injURL, param, kind, sink string
	err := h.db.QueryRowContext(ctx, `
		SELECT target_id, url, parameter, kind, sink
		FROM oob_probes WHERE token = ?`, token).
		Scan(&targetID, &injURL, &param, &kind, &sink)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			h.logger.Error("Failed to look up OOB probe", "token", token, "error", err)
		}
		return false // unknown token — ignore stray traffic
	}

	vulnType := oobVulnType(kind)
	evidence := fmt.Sprintf(
		"Out-of-band %s confirmed: the target server called back via %s. Injected via %s (sink: %s). Source IP: %s | method: %s | UA: %s",
		vulnType, via, injURL, sink, srcIP, method, ua)

	obs := scanner.DetectorObservation{
		TargetID: targetID, Type: vulnType, Subtype: kind, Severity: "critical",
		URL: injURL, Method: "CALLBACK", Parameter: param, Location: sink,
		Payload: "oob token=" + token, Evidence: evidence, Source: "oast-callback",
		DetectionMethod: via, Confidence: 100, Priority: 500, Verdict: scanner.VerifyVerified,
	}
	if _, err = scanner.RecordDetectorObservation(ctx, h.db, obs); isSQLiteBusy(err) {
		select {
		case <-time.After(200 * time.Millisecond):
			_, err = scanner.RecordDetectorObservation(ctx, h.db, obs)
		case <-ctx.Done():
		}
	}
	if err != nil {
		h.logger.Error("Failed to record OOB detector observation", "token", token, "kind", kind, "target", targetID, "src", srcIP, "via", via, "error", err)
		return false
	}

	var newHits int
	updateErr := h.db.QueryRowContext(ctx, `
		UPDATE oob_probes
		SET hit_count = hit_count + 1, last_hit = CURRENT_TIMESTAMP, evidence = ?
		WHERE token = ?
		RETURNING hit_count`, evidence, token).Scan(&newHits)
	if isSQLiteBusy(updateErr) {
		select {
		case <-time.After(200 * time.Millisecond):
			updateErr = h.db.QueryRowContext(ctx, `
				UPDATE oob_probes
				SET hit_count = hit_count + 1, last_hit = CURRENT_TIMESTAMP, evidence = ?
				WHERE token = ?
				RETURNING hit_count`, evidence, token).Scan(&newHits)
		case <-ctx.Done():
		}
	}
	if updateErr != nil {
		h.logger.Error("Failed to update OOB probe stats", "token", token, "kind", kind, "target", targetID, "error", updateErr)
	}

	if updateErr == nil && newHits == 1 && h.sched != nil {
		h.sched.EmitVulnFinding(map[string]any{
			"target_id": targetID, "type": vulnType, "url": injURL, "parameter": param,
		})
	}
	h.logger.Warn("OAST callback fired", "token", token, "kind", kind, "target", targetID, "src", srcIP, "via", via)
	return true
}
