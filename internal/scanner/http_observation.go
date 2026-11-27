package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// Observation paths are deliberately distinct. A breadth probe and a deep
// probe can observe the same stable redirect with different codes; they must
// establish independent baselines instead of manufacturing a transition.
const (
	ObservationWatch   = "watch_http"
	ObservationDeep    = "deep_http"
	ObservationMonitor = "monitor"
)

type HTTPObservation struct {
	TargetID          string
	TaskID            string
	URL               string
	Host              string
	SubdomainID       string
	StatusCode        int
	Title             string
	Server            string
	Technologies      string // JSON array
	RedirectURL       string
	BodyHash          string
	ContentType       string
	ContentLength     int
	Source            string
	ProbeTier         string
	Type              string
	PinBaselineStatus bool
}

type observedChange struct {
	ID         string
	ChangeType string
	OldValue   string
	NewValue   string
	Severity   string
	OldStatus  int
	NewStatus  int
	Metadata   string
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// NormalizeServiceURL keeps the scheme, effective port, path and query. It
// removes only case and trailing-dot noise in the host, so two distinct
// endpoints never share a baseline by accident.
func NormalizeServiceURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.ToLower(s)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return strings.ToLower(s)
	}
	hostPart := host
	if port := u.Port(); port != "" {
		hostPart = net.JoinHostPort(host, port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := strings.ToLower(u.Scheme) + "://" + hostPart + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// ValidHTTPStatus reports whether a code is a real HTTP observation. Status 0
// and out-of-range codes mean unknown and never create a transition.
func ValidHTTPStatus(code int) bool {
	return code >= 100 && code <= 599
}

// isRedirectStatus reports whether code is a standard HTTP redirect status.
func isRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// normalizeRedirectTarget canonicalizes a redirect Location/final_url against
// baseURL for destination-equivalence comparison. It resolves relative and
// scheme-relative targets, lowercases scheme/host, strips trailing dots, default
// ports (http:80, https:443), fragments, and query strings (so volatile SSO/OAuth
// state/nonce/csrf query params do not trigger constant redirect_change noise).
func normalizeRedirectTarget(baseURL, rawLocation string) string {
	raw := strings.TrimSpace(rawLocation)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			raw = raw[:idx]
		}
		return strings.ToLower(strings.TrimSpace(raw))
	}
	if base := strings.TrimSpace(baseURL); base != "" {
		if bu, berr := url.Parse(base); berr == nil && bu.Scheme != "" && bu.Host != "" {
			u = bu.ResolveReference(u)
		}
	}
	if u.Scheme == "" || u.Host == "" {
		u.RawQuery = ""
		u.Fragment = ""
		return strings.ToLower(strings.TrimSpace(u.String()))
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		u.RawQuery = ""
		u.Fragment = ""
		return strings.ToLower(strings.TrimSpace(u.String()))
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostPart := host
	if port != "" {
		hostPart = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		hostPart = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + hostPart + path
}

// isEquivalentRedirectStatus reports whether two redirect status codes point to
// the same destination (or the prior baseline had no recorded target yet, for
// pre-upgrade compatibility), so 301 <-> 302 edge/CDN alternation is suppressed.
func isEquivalentRedirectStatus(baseURL string, oldCode, newCode int, oldTarget, newTarget string) bool {
	if !isRedirectStatus(oldCode) || !isRedirectStatus(newCode) {
		return false
	}
	oldNorm := normalizeRedirectTarget(baseURL, oldTarget)
	if oldNorm == "" {
		return true
	}
	return oldNorm == normalizeRedirectTarget(baseURL, newTarget)
}

// isRedirectBoilerplateTitle reports whether title is empty or a standard
// proxy/CDN redirect boilerplate title (e.g. "301 Moved Permanently", "302 Found").
func isRedirectBoilerplateTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	if t == "" {
		return true
	}
	switch t {
	case "301 moved permanently",
		"302 found",
		"302 moved temporarily",
		"303 see other",
		"307 temporary redirect",
		"308 permanent redirect",
		"moved permanently",
		"found",
		"moved temporarily",
		"temporary redirect",
		"permanent redirect",
		"object moved":
		return true
	}
	for _, pfx := range []string{"301 ", "302 ", "303 ", "307 ", "308 "} {
		if strings.HasPrefix(t, pfx) {
			return true
		}
	}
	return false
}

type observationBaseline struct {
	status   int
	title    string
	server   string
	tech     string
	redirect string
	bodyHash string
}

func readBaseline(ctx context.Context, tx *sql.Tx, targetID, serviceURL, obsType string) (observationBaseline, bool, error) {
	var b observationBaseline
	err := tx.QueryRowContext(ctx, `
		SELECT status_code, title, server, technologies, redirect_url, body_hash
		FROM http_observation_baselines
		WHERE target_id=? AND service_url=? AND observation_type=?`,
		targetID, serviceURL, obsType).Scan(&b.status, &b.title, &b.server, &b.tech, &b.redirect, &b.bodyHash)
	if err == nil {
		return b, true, nil
	}
	if err != sql.ErrNoRows {
		return b, false, err
	}

	// Seed only from a row whose provenance is known. A seed row (source='seed',
	// status 0) or a row written by another tier is not a reliable baseline.
	var source, tier string
	err = tx.QueryRowContext(ctx, `
		SELECT status_code, COALESCE(title,''), COALESCE(server,''),
		       COALESCE(technologies,'[]'), COALESCE(redirect_url,''),
		       COALESCE(source,'probe'), COALESCE(probe_tier,'')
		FROM http_services WHERE target_id=? AND url=?`,
		targetID, serviceURL).Scan(&b.status, &b.title, &b.server, &b.tech, &b.redirect, &source, &tier)
	if err != nil {
		return observationBaseline{}, false, nil
	}
	reliable := source == "probe" && ValidHTTPStatus(b.status)
	// An empty tier marks a row written before tiers existed. Its probe source
	// is still reliable; a seed row is excluded above by source != probe.
	if obsType == ObservationWatch {
		reliable = reliable && (tier == "watch" || tier == "")
	} else if obsType == ObservationDeep {
		reliable = reliable && (tier == "deep" || tier == "")
	} else if obsType == ObservationMonitor {
		// The monitor compares against its own committed view. A watch-round
		// row is never a valid monitor baseline.
		reliable = reliable && (tier == "deep" || tier == "")
	}
	if !reliable {
		return observationBaseline{}, false, nil
	}
	return b, true, nil
}

func (s *HTTPScanner) preloadBaselines(ctx context.Context, targetID, obsType string) map[string]observationBaseline {
	out := map[string]observationBaseline{}
	if s == nil || s.db == nil || targetID == "" || obsType == "" {
		return out
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT service_url, status_code, title, server, technologies, redirect_url, body_hash
		FROM http_observation_baselines
		WHERE target_id=? AND observation_type=?`,
		targetID, obsType)
	if err == nil {
		for rows.Next() {
			var serviceURL string
			var b observationBaseline
			if rows.Scan(&serviceURL, &b.status, &b.title, &b.server, &b.tech, &b.redirect, &b.bodyHash) == nil && serviceURL != "" {
				out[serviceURL] = b
			}
		}
		rows.Close()
	}

	svcRows, err := s.db.QueryContext(ctx, `
		SELECT url, status_code, COALESCE(title,''), COALESCE(server,''),
		       COALESCE(technologies,'[]'), COALESCE(redirect_url,''),
		       COALESCE(source,'probe'), COALESCE(probe_tier,'')
		FROM http_services
		WHERE target_id=?`,
		targetID)
	if err == nil {
		for svcRows.Next() {
			var rawURL, source, tier string
			var b observationBaseline
			if svcRows.Scan(&rawURL, &b.status, &b.title, &b.server, &b.tech, &b.redirect, &source, &tier) != nil {
				continue
			}
			serviceURL := NormalizeServiceURL(rawURL)
			if serviceURL == "" {
				continue
			}
			if _, exists := out[serviceURL]; exists {
				continue
			}
			reliable := source == "probe" && ValidHTTPStatus(b.status)
			if obsType == ObservationWatch {
				reliable = reliable && (tier == "watch" || tier == "")
			} else if obsType == ObservationDeep {
				reliable = reliable && (tier == "deep" || tier == "")
			} else if obsType == ObservationMonitor {
				reliable = reliable && (tier == "deep" || tier == "")
			}
			if reliable {
				out[serviceURL] = b
			}
		}
		svcRows.Close()
	}
	return out
}

func compareObservation(baseURL string, b observationBaseline, obs HTTPObservation) ([]observedChange, int, string) {
	var out []observedChange
	effectiveStatus := obs.StatusCode
	effectiveTitle := obs.Title

	if obs.PinBaselineStatus && ValidHTTPStatus(b.status) {
		effectiveStatus = b.status
		if b.title != "" || isRedirectBoilerplateTitle(obs.Title) {
			effectiveTitle = b.title
		}
	} else if ValidHTTPStatus(b.status) && ValidHTTPStatus(obs.StatusCode) && b.status != obs.StatusCode {
		if isEquivalentRedirectStatus(baseURL, b.status, obs.StatusCode, b.redirect, obs.RedirectURL) {
			effectiveStatus = b.status
			if isRedirectBoilerplateTitle(b.title) && isRedirectBoilerplateTitle(obs.Title) {
				effectiveTitle = b.title
			}
		} else {
			out = append(out, observedChange{
				ChangeType: "status_change",
				OldValue:   fmt.Sprintf("status=%d title=%s", b.status, b.title),
				NewValue:   fmt.Sprintf("status=%d title=%s", obs.StatusCode, obs.Title),
				Severity:   "medium",
				OldStatus:  b.status,
				NewStatus:  obs.StatusCode,
				Metadata:   fmt.Sprintf(`{"old_code":%d,"new_code":%d,"source":%q}`, b.status, obs.StatusCode, obs.Type),
			})
		}
	}
	if ValidHTTPStatus(b.status) && isEquivalentRedirectStatus(baseURL, b.status, effectiveStatus, b.redirect, obs.RedirectURL) &&
		isRedirectBoilerplateTitle(b.title) && isRedirectBoilerplateTitle(effectiveTitle) {
		effectiveTitle = b.title
	}
	if b.title != effectiveTitle {
		out = append(out, observedChange{
			ChangeType: "page_change", OldValue: b.title, NewValue: effectiveTitle, Severity: "low",
			Metadata: fmt.Sprintf(`{"source":%q}`, obs.Type),
		})
	}
	oldTech := fmt.Sprintf("Server: %s | Tech: %s", b.server, b.tech)
	newTech := fmt.Sprintf("Server: %s | Tech: %s", obs.Server, obs.Technologies)
	if oldTech != newTech {
		out = append(out, observedChange{
			ChangeType: "tech_change", OldValue: oldTech, NewValue: newTech, Severity: "low",
			Metadata: fmt.Sprintf(`{"source":%q}`, obs.Type),
		})
	}
	// Silent upgrade backfill: pre-upgrade baselines have empty redirect_url on
	// 3xx rows. Persist obs.RedirectURL silently without firing redirect_change.
	silentBackfill := strings.TrimSpace(b.redirect) == "" && isRedirectStatus(b.status) && strings.TrimSpace(obs.RedirectURL) != ""
	if !silentBackfill {
		oldNorm := normalizeRedirectTarget(baseURL, b.redirect)
		newNorm := normalizeRedirectTarget(baseURL, obs.RedirectURL)
		if oldNorm != newNorm && (oldNorm != "" || newNorm != "" || isRedirectStatus(b.status) != isRedirectStatus(effectiveStatus)) {
			out = append(out, observedChange{
				ChangeType: "redirect_change",
				OldValue:   b.redirect,
				NewValue:   obs.RedirectURL,
				Severity:   "low",
				OldStatus:  b.status,
				NewStatus:  effectiveStatus,
				Metadata:   fmt.Sprintf(`{"source":%q}`, obs.Type),
			})
		}
	}
	if b.bodyHash != "" && obs.BodyHash != "" && b.bodyHash != obs.BodyHash {
		out = append(out, observedChange{
			ChangeType: "content_change", OldValue: b.bodyHash, NewValue: obs.BodyHash, Severity: "low",
			Metadata: fmt.Sprintf(`{"source":%q}`, obs.Type),
		})
	}
	return out, effectiveStatus, effectiveTitle
}

// upsertObservationBaseline advances a comparison baseline. An unknown code
// must never replace a valid sample: a failed connect (status 0) would erase
// the baseline and hide the next real transition.
type execContexter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func upsertObservationBaseline(ctx context.Context, exec execContexter, targetID, serviceURL, obsType string,
	statusCode int, title, server, technologies, redirectURL, bodyHash string) error {
	if !ValidHTTPStatus(statusCode) {
		return nil
	}
	_, err := exec.ExecContext(ctx, `
		INSERT INTO http_observation_baselines
			(target_id,service_url,observation_type,status_code,title,server,technologies,redirect_url,body_hash,detected_at)
		VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(target_id,service_url,observation_type) DO UPDATE SET
			status_code=excluded.status_code, title=excluded.title, server=excluded.server,
			technologies=excluded.technologies, redirect_url=excluded.redirect_url,
			body_hash=excluded.body_hash, detected_at=CURRENT_TIMESTAMP`,
		targetID, serviceURL, obsType, statusCode, title, server, technologies, redirectURL, bodyHash)
	return err
}

// recordObservation commits the comparison baseline, the change events, the
// bell entries and the service inventory in one transaction. Nothing is
// published until commit, so a failed event write cannot advance the baseline
// on its own. The caller retries the observation if this returns an error.
func (s *HTTPScanner) recordObservation(ctx context.Context, obs HTTPObservation) error {
	_, err := s.recordObservationWithEffectiveStatus(ctx, obs)
	return err
}

func (s *HTTPScanner) recordObservationWithEffectiveStatus(ctx context.Context, obs HTTPObservation) (int, error) {
	serviceURL := NormalizeServiceURL(obs.URL)
	if obs.TargetID == "" || serviceURL == "" || obs.Type == "" {
		return 0, fmt.Errorf("incomplete HTTP observation")
	}
	if obs.Type != ObservationWatch && obs.Type != ObservationDeep && obs.Type != ObservationMonitor {
		return 0, fmt.Errorf("unknown HTTP observation type %q", obs.Type)
	}
	// A status-zero response is not an observation. Never let it replace a
	// valid baseline or the last good service row.
	if !ValidHTTPStatus(obs.StatusCode) {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	baseline, hadBaseline, err := readBaseline(ctx, tx, obs.TargetID, serviceURL, obs.Type)
	if err != nil {
		return 0, err
	}
	changes := []observedChange{}
	effectiveStatus := obs.StatusCode
	effectiveTitle := obs.Title
	effectiveRedirect := obs.RedirectURL
	if hadBaseline {
		if obs.PinBaselineStatus && strings.TrimSpace(obs.RedirectURL) == "" && strings.TrimSpace(baseline.redirect) != "" {
			obs.RedirectURL = baseline.redirect
			effectiveRedirect = baseline.redirect
		}
		changes, effectiveStatus, effectiveTitle = compareObservation(serviceURL, baseline, obs)
	}

	var events []observedChange
	for _, c := range changes {
		c.ID = uuid.NewString()
		if obs.Type == ObservationWatch {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO watch_round_changes
					(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,old_status,new_status,detected_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`,
				c.ID, obs.TargetID, obs.TaskID, serviceURL, c.ChangeType, c.OldValue, c.NewValue,
				c.Severity, c.Metadata, c.OldStatus, c.NewStatus)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO monitoring_changes
					(id,target_id,url,change_type,old_value,new_value,severity,old_status,new_status,detected_at)
				VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`,
				c.ID, obs.TargetID, serviceURL, c.ChangeType, c.OldValue, c.NewValue,
				c.Severity, c.OldStatus, c.NewStatus)
		}
		if err != nil {
			return 0, fmt.Errorf("write %s event: %w", c.ChangeType, err)
		}
		if c.ChangeType == "status_change" {
			title := notificationTitle(c.ChangeType)
			body := serviceURL
			if c.NewValue != "" {
				body = serviceURL + " — " + c.NewValue
			}
			if _, err = tx.ExecContext(ctx, `
				INSERT INTO notifications
					(id,target_id,type,title,body,url,severity,is_read,metadata,change_id,old_value,new_value,created_at)
				VALUES (?,?,?,?,?,?,?,0,?,?,?,?,CURRENT_TIMESTAMP)`,
				uuid.NewString(), obs.TargetID, c.ChangeType, title, body, serviceURL,
				c.Severity, c.Metadata, c.ID, c.OldValue, c.NewValue); err != nil {
				return 0, fmt.Errorf("write %s bell entry: %w", c.ChangeType, err)
			}
		}
		events = append(events, c)
	}

	if err = upsertObservationBaseline(ctx, tx, obs.TargetID, serviceURL, obs.Type,
		effectiveStatus, effectiveTitle, obs.Server, obs.Technologies, effectiveRedirect, obs.BodyHash); err != nil {
		return 0, fmt.Errorf("update observation baseline: %w", err)
	}

	source := obs.Source
	if source == "" {
		source = "probe"
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO http_services
			(id,target_id,subdomain_id,url,status_code,title,server,content_type,content_length,
			 redirect_url,technologies,probe_tier,source,last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(target_id,url) DO UPDATE SET
			status_code=excluded.status_code, title=excluded.title, server=excluded.server,
			content_type=excluded.content_type, content_length=excluded.content_length,
			redirect_url=excluded.redirect_url, technologies=excluded.technologies,
			probe_tier=excluded.probe_tier, last_seen=CURRENT_TIMESTAMP,
			subdomain_id=COALESCE(excluded.subdomain_id, http_services.subdomain_id),
			source=CASE WHEN COALESCE(http_services.source,'')='seed' THEN 'probe' ELSE http_services.source END`,
		uuid.NewString(), obs.TargetID, nullableString(obs.SubdomainID), serviceURL,
		effectiveStatus, effectiveTitle, obs.Server, obs.ContentType, obs.ContentLength,
		effectiveRedirect, obs.Technologies, obs.ProbeTier, source); err != nil {
		return 0, fmt.Errorf("update service inventory: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, err
	}
	if len(events) > 0 && s.broadcast != nil {
		s.broadcast("changes_written", map[string]any{"target_id": obs.TargetID, "count": len(events)})
	}
	for _, c := range events {
		if s.broadcast == nil || c.ChangeType != "status_change" {
			continue
		}
		s.broadcast("notification_created", map[string]any{
			"target_id": obs.TargetID, "type": c.ChangeType, "severity": c.Severity,
			"change_id": c.ID, "old_value": c.OldValue, "new_value": c.NewValue,
			"old_status": c.OldStatus, "new_status": c.NewStatus, "url": serviceURL,
		})
	}
	return effectiveStatus, nil
}
