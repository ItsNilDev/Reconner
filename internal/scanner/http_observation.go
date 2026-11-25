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
	TargetID      string
	TaskID        string
	URL           string
	Host          string
	SubdomainID   string
	StatusCode    int
	Title         string
	Server        string
	Technologies  string // JSON array
	RedirectURL   string
	BodyHash      string
	ContentType   string
	ContentLength int
	Source        string
	ProbeTier     string
	Type          string
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

func compareObservation(b observationBaseline, obs HTTPObservation) []observedChange {
	var out []observedChange
	if ValidHTTPStatus(b.status) && ValidHTTPStatus(obs.StatusCode) && b.status != obs.StatusCode {
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
	if b.title != obs.Title {
		out = append(out, observedChange{
			ChangeType: "page_change", OldValue: b.title, NewValue: obs.Title, Severity: "low",
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
	if b.redirect != obs.RedirectURL {
		out = append(out, observedChange{
			ChangeType: "redirect_change", OldValue: b.redirect, NewValue: obs.RedirectURL, Severity: "low",
			Metadata: fmt.Sprintf(`{"source":%q}`, obs.Type),
		})
	}
	if b.bodyHash != "" && obs.BodyHash != "" && b.bodyHash != obs.BodyHash {
		out = append(out, observedChange{
			ChangeType: "content_change", OldValue: b.bodyHash, NewValue: obs.BodyHash, Severity: "low",
			Metadata: fmt.Sprintf(`{"source":%q}`, obs.Type),
		})
	}
	return out
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
	serviceURL := NormalizeServiceURL(obs.URL)
	if obs.TargetID == "" || serviceURL == "" || obs.Type == "" {
		return fmt.Errorf("incomplete HTTP observation")
	}
	if obs.Type != ObservationWatch && obs.Type != ObservationDeep && obs.Type != ObservationMonitor {
		return fmt.Errorf("unknown HTTP observation type %q", obs.Type)
	}
	// A status-zero response is not an observation. Never let it replace a
	// valid baseline or the last good service row.
	if !ValidHTTPStatus(obs.StatusCode) {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	baseline, hadBaseline, err := readBaseline(ctx, tx, obs.TargetID, serviceURL, obs.Type)
	if err != nil {
		return err
	}
	changes := []observedChange{}
	if hadBaseline {
		changes = compareObservation(baseline, obs)
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
			return fmt.Errorf("write %s event: %w", c.ChangeType, err)
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
				return fmt.Errorf("write %s bell entry: %w", c.ChangeType, err)
			}
		}
		events = append(events, c)
	}

	if err = upsertObservationBaseline(ctx, tx, obs.TargetID, serviceURL, obs.Type,
		obs.StatusCode, obs.Title, obs.Server, obs.Technologies, obs.RedirectURL, obs.BodyHash); err != nil {
		return fmt.Errorf("update observation baseline: %w", err)
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
		obs.StatusCode, obs.Title, obs.Server, obs.ContentType, obs.ContentLength,
		obs.RedirectURL, obs.Technologies, obs.ProbeTier, source); err != nil {
		return fmt.Errorf("update service inventory: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return err
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
	return nil
}
