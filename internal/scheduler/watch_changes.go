package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scanner"
)

// watchChange is one row in the long-lived watch round audit trail. Details
// rows (status, title, tech, redirect) stay in this table for the detail tier,
// but only new_subdomain reaches the default Changes feed.
type watchChange struct {
	URL        string
	ChangeType string
	OldValue   string
	NewValue   string
	Severity   string
	Metadata   string // JSON object
	OldStatus  int    // numeric HTTP codes for a status_change row
	NewStatus  int
}

type watchHTTPSnapshot struct {
	URL          string
	StatusCode   int
	Title        string
	Server       string
	Technologies string
	RedirectURL  string
}

func joinWatchTechnologies(raw string) string {
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err == nil {
		sort.Strings(list)
		return strings.Join(list, ", ")
	}
	return strings.Trim(raw, "[]\"")
}

type watchHostCandidate struct {
	Host         string
	FirstSeenAt  string
	FirstAliveAt string
	InScope      bool
	ProgramID    string
	AssetID      string
	Service      watchHTTPSnapshot
	Score        int
	Fingerprint  string
}

// emitWatchNewHosts writes the single new_subdomain event for each host that
// is first seen alive in this round. The event row and its announced marker are
// written in one transaction, so a crash can never duplicate an announcement.
// The first finished watch round is a baseline and announces nothing.
func (s *Scheduler) emitWatchNewHosts(ctx context.Context, taskID, targetID string) []watchChange {
	finished := 0
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tasks
		WHERE target_id=? AND type=? AND status='finished' AND id<>?`,
		targetID, watchScanType, taskID).Scan(&finished); err != nil {
		s.logger.Warn("watch new-host: baseline check failed", "error", err)
		return nil
	}
	if finished == 0 {
		announcedPrior := 0
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watch_hosts
			WHERE target_id=? AND announced_at IS NOT NULL`, targetID).Scan(&announcedPrior); err != nil {
			s.logger.Warn("watch new-host: prior baseline check failed", "error", err)
			return nil
		}
		if announcedPrior == 0 {
			s.baselineWatchHosts(ctx, targetID)
			return nil
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT w.host, COALESCE(w.first_seen_at,''), COALESCE(w.first_alive_at,''),
			COALESCE(w.program_id,''), COALESCE(w.asset_id,''), COALESCE(s.is_alive,0)
		FROM watch_hosts w
		LEFT JOIN subdomains s ON s.target_id=w.target_id AND s.subdomain=w.host
		WHERE w.target_id=? AND w.first_alive_at IS NOT NULL AND w.announced_at IS NULL
		ORDER BY w.first_alive_at, w.host`, targetID)
	if err != nil {
		s.logger.Warn("watch new-host: candidate query failed", "error", err)
		return nil
	}
	type rawCandidate struct {
		host, firstSeen, firstAlive, programID, assetID string
		alive                                           bool
	}
	var raw []rawCandidate
	for rows.Next() {
		var c rawCandidate
		var alive int
		if err := rows.Scan(&c.host, &c.firstSeen, &c.firstAlive, &c.programID, &c.assetID, &alive); err != nil {
			_ = rows.Close()
			s.logger.Warn("watch new-host: candidate scan failed", "error", err)
			return nil
		}
		c.alive = alive == 1
		raw = append(raw, c)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Warn("watch new-host: candidate rows error", "error", err)
		return nil
	}

	// Manual breadth projects use the project's effective scope. Linked
	// projects add program eligibility as a separate requirement. A scope read
	// failure leaves eligibility unknown, so the host is not announced.
	state, scopeErr := s.loadTaskScopeState(ctx, targetID)
	if scopeErr != nil {
		s.logger.Warn("watch new-host: scope could not be read", "error", scopeErr)
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	svcByHost, svcErr := batchWatchHTTPServices(ctx, s.db, targetID)
	if svcErr != nil {
		s.logger.Warn("watch new-host: http services query failed", "error", svcErr)
		return nil
	}

	candidates := make([]watchHostCandidate, 0, len(raw))
	for _, c := range raw {
		if !c.alive {
			continue
		}
		// A wildcard scope pattern is not an observable host. Never emit it as
		// a new host and never label it in or out of scope.
		if scanner.IsWildcardScopePattern(c.host) {
			// Close the bad row so it cannot stay pending every round.
			if _, err := s.db.ExecContext(ctx, `UPDATE watch_hosts SET announced_at=CURRENT_TIMESTAMP
				WHERE target_id=? AND host=?`, targetID, c.host); err != nil {
				s.logger.Warn("watch new-host: wildcard marker failed", "host", c.host, "error", err)
			}
			continue
		}
		inScope, programID, assetID := false, c.programID, c.assetID
		if state.linked {
			inScope, programID, assetID = scanner.MatchWatchEligibleHost(ctx, state.entries, state.exclusions, c.host)
			if !inScope {
				programID, assetID = c.programID, c.assetID
			}
		} else {
			inScope = state.allowsProjectHost(ctx, c.host)
		}
		svc := svcByHost[normalizeWatchedHost(c.host)]
		candidates = append(candidates, watchHostCandidate{
			Host: c.host, FirstSeenAt: c.firstSeen, FirstAliveAt: c.firstAlive,
			InScope: inScope, ProgramID: programID, AssetID: assetID,
			Service: svc, Score: scoreWatchCandidate(svc, inScope),
			Fingerprint: watchFingerprint(svc),
		})
	}
	if len(candidates) == 0 {
		return nil
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].InScope != candidates[j].InScope {
			return candidates[i].InScope
		}
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Host < candidates[j].Host
	})

	// Fold identical responses into one event. The representative carries the
	// probed URL; fleet metadata carries every host in the group.
	groups := make([]watchHostCandidate, 0, len(candidates))
	// Keep scope per member. One in-scope host in a fleet must not label every
	// other member as in scope (A9).
	members := make(map[string][]map[string]any, len(candidates))
	byFP := map[string]int{}
	for _, c := range candidates {
		if idx, ok := byFP[c.Fingerprint]; ok {
			members[c.Fingerprint] = append(members[c.Fingerprint], map[string]any{"host": c.Host, "in_scope": c.InScope})
			if !groups[idx].InScope && c.InScope {
				groups[idx].InScope = true
				groups[idx].Host = c.Host
				groups[idx].Service = c.Service
				groups[idx].ProgramID = c.ProgramID
				groups[idx].AssetID = c.AssetID
			}
			continue
		}
		byFP[c.Fingerprint] = len(groups)
		groups = append(groups, c)
		members[c.Fingerprint] = []map[string]any{{"host": c.Host, "in_scope": c.InScope}}
	}

	capK := 20
	if s.cfg != nil && s.cfg.WatchNotifyHostCap > 0 {
		capK = s.cfg.WatchNotifyHostCap
	}
	visible := groups
	truncated := 0
	if len(visible) > capK {
		visible = visible[:capK]
		for _, g := range groups[capK:] {
			truncated += len(members[g.Fingerprint])
		}
	}

	changes := make([]watchChange, 0, len(visible)+1)
	for _, g := range visible {
		memberRows := members[g.Fingerprint]
		hosts := make([]string, 0, len(memberRows))
		for _, m := range memberRows {
			if h, ok := m["host"].(string); ok {
				hosts = append(hosts, h)
			}
		}
		statusLabel := "DNS discovery"
		statusKnown := false
		if scanner.ValidHTTPStatus(g.Service.StatusCode) {
			statusLabel = fmt.Sprintf("HTTP %d", g.Service.StatusCode)
			statusKnown = true
		}
		meta := map[string]any{
			"host": g.Host, "hosts": hosts, "members": memberRows, "fleet.size": len(hosts),
			"status": g.Service.StatusCode, "status_label": statusLabel,
			"status_known": statusKnown, "title": g.Service.Title,
			"server": g.Service.Server, "tech": watchTechList(g.Service.Technologies),
			"ip": "", "source": "watch", "in_scope": g.InScope,
			"first_seen_at": g.FirstSeenAt, "first_alive_at": g.FirstAliveAt,
			"total": len(hosts), "truncated": false,
		}
		b, _ := json.Marshal(meta)
		changes = append(changes, watchChange{
			URL: g.Service.URL, ChangeType: "new_subdomain",
			NewValue: g.Host, Severity: newHostSeverity(g.Service.StatusCode),
			Metadata: string(b),
		})
	}
	if truncated > 0 {
		all := make([]string, 0, truncated)
		for _, g := range groups[capK:] {
			for _, m := range members[g.Fingerprint] {
				if h, ok := m["host"].(string); ok {
					all = append(all, h)
				}
			}
		}
		b, _ := json.Marshal(map[string]any{
			"hosts": all, "total": truncated, "truncated": true,
		})
		changes = append(changes, watchChange{
			ChangeType: "new_subdomain", Severity: "info", Metadata: string(b),
		})
	}

	// One transaction for every event and every marker. Out-of-scope hosts are
	// marked announced too: they stay in the lifecycle but never reach the feed.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Warn("watch new-host: begin failed", "error", err)
		return nil
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO watch_round_changes
		(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`)
	if err != nil {
		s.logger.Warn("watch new-host: prepare failed", "error", err)
		return nil
	}
	for _, c := range changes {
		if _, err := stmt.ExecContext(ctx, uuid.New().String(), targetID, taskID, c.URL,
			c.ChangeType, c.OldValue, c.NewValue, c.Severity, c.Metadata); err != nil {
			_ = stmt.Close()
			s.logger.Warn("watch new-host: insert failed", "error", err)
			return nil
		}
	}
	_ = stmt.Close()
	const hostChunkSize = 500
	for start := 0; start < len(candidates); start += hostChunkSize {
		end := start + hostChunkSize
		if end > len(candidates) {
			end = len(candidates)
		}
		chunk := candidates[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, 0, len(chunk)+1)
		args = append(args, targetID)
		for _, c := range chunk {
			args = append(args, c.Host)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE watch_hosts SET announced_at=CURRENT_TIMESTAMP
			WHERE target_id=? AND announced_at IS NULL AND host IN (`+placeholders+`)`, args...); err != nil {
			s.logger.Warn("watch new-host: marker update failed", "error", err)
			return nil
		}
	}
	if err := tx.Commit(); err != nil {
		s.logger.Warn("watch new-host: commit failed", "error", err)
		return nil
	}
	if s.hub != nil {
		s.hub.Broadcast("changes_written", map[string]any{"target_id": targetID, "count": len(changes)})
	}
	// One grouped alert per round. Out-of-scope hosts stay in the audit table
	// but never reach the bell or Telegram.
	notifyHosts := make([]string, 0, len(candidates))
	for _, g := range groups {
		for _, m := range members[g.Fingerprint] {
			if host, ok := m["host"].(string); ok && !scanner.IsWildcardScopePattern(host) {
				// Per-member scope wins over the fleet-level flag.
				inScope, _ := m["in_scope"].(bool)
				if inScope {
					notifyHosts = append(notifyHosts, host)
				}
			}
		}
	}
	if len(notifyHosts) > 0 {
		var domain string
		if err := s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain); err != nil {
			s.logger.Warn("watch new-host: target domain lookup failed", "target_id", targetID, "error", err)
		}
		summary := fmt.Sprintf("%d new host(s) up on %s", len(notifyHosts), domain)
		previewHosts := notifyHosts
		if len(previewHosts) > 500 {
			previewHosts = previewHosts[:500]
		}
		metaBytes, err := json.Marshal(map[string]any{
			"source":  "watch",
			"hosts":   previewHosts,
			"total":   len(notifyHosts),
			"task_id": taskID,
		})
		if err != nil {
			s.logger.Warn("watch new-host: notification metadata marshal failed", "error", err)
			metaBytes = []byte(`{"source":"watch"}`)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO notifications
			(id,target_id,type,title,body,url,severity,is_read,metadata)
			VALUES (?,?,?,?,?,?,?,0,?)`,
			uuid.New().String(), targetID, "new_host", "New hosts up", summary,
			"/targets/"+targetID, "info", string(metaBytes)); err != nil {
			s.logger.Warn("watch new-host: notification insert failed", "target_id", targetID, "error", err)
		} else if s.hub != nil {
			s.hub.Broadcast("notification_created", map[string]any{
				"target_id": targetID,
				"type":      "new_host",
				"severity":  "info",
			})
		}
		if s.notifier != nil {
			s.notifier.NotifyNewHosts("newhost:"+taskID, summary, notifyHosts, targetID)
		}
	}
	return changes
}

func (s *Scheduler) baselineWatchHosts(ctx context.Context, targetID string) {
	_, err := s.db.ExecContext(ctx, `UPDATE watch_hosts SET announced_at=CURRENT_TIMESTAMP
		WHERE target_id=? AND announced_at IS NULL AND first_alive_at IS NOT NULL`, targetID)
	if err != nil {
		s.logger.Warn("watch new-host: baseline marker failed", "error", err)
	}
}

func normalizeWatchedHost(raw string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func scanWatchService(scannerRow interface {
	Scan(dest ...any) error
}) (watchHTTPSnapshot, error) {
	var h watchHTTPSnapshot
	var tech string
	err := scannerRow.Scan(&h.URL, &h.StatusCode, &h.Title, &h.Server, &tech, &h.RedirectURL)
	if err != nil {
		return watchHTTPSnapshot{}, err
	}
	h.Technologies = joinWatchTechnologies(tech)
	return h, nil
}

// batchWatchHTTPServices loads the best valid HTTP service (status 100–599,
// preferring https://) for every host of targetID in a single query.
func batchWatchHTTPServices(ctx context.Context, db *database.DB, targetID string) (map[string]watchHTTPSnapshot, error) {
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(d.subdomain,''), COALESCE(s.url,''),
		COALESCE(s.status_code,0), COALESCE(s.title,''), COALESCE(s.server,''),
		COALESCE(s.technologies,'[]'), COALESCE(s.redirect_url,'')
		FROM http_services s LEFT JOIN subdomains d ON d.id=s.subdomain_id
		WHERE s.target_id=? AND COALESCE(s.status_code,0) BETWEEN 100 AND 599
		ORDER BY CASE WHEN d.id IS NOT NULL THEN 0 ELSE 1 END,
		         CASE WHEN LOWER(s.url) LIKE 'https://%' THEN 0 ELSE 1 END, s.url`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]watchHTTPSnapshot)
	for rows.Next() {
		var subdomain, tech string
		var h watchHTTPSnapshot
		if err := rows.Scan(&subdomain, &h.URL, &h.StatusCode, &h.Title, &h.Server, &tech, &h.RedirectURL); err != nil {
			return nil, err
		}
		host := normalizeWatchedHost(subdomain)
		if host == "" {
			host = normalizeWatchedHost(scanner.URLHost(h.URL))
		}
		if host == "" {
			continue
		}
		if _, exists := out[host]; exists {
			continue
		}
		h.Technologies = joinWatchTechnologies(tech)
		out[host] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// watchHTTPServiceForHost matches a host exactly. A prefix LIKE would let
// a.example.test.evil borrow the service of a.example.test. The subdomain_id
// relation is authoritative when present; otherwise the URL host is compared
// after normalization.
func watchHTTPServiceForHost(ctx context.Context, db *database.DB, targetID, host string) watchHTTPSnapshot {
	wanted := normalizeWatchedHost(host)
	if wanted == "" {
		return watchHTTPSnapshot{}
	}
	selectCols := `SELECT COALESCE(s.url,''),COALESCE(s.status_code,0),COALESCE(s.title,''),
		COALESCE(s.server,''),COALESCE(s.technologies,'[]'),COALESCE(s.redirect_url,'')`
	if h, err := scanWatchService(db.QueryRowContext(ctx, selectCols+`
		FROM http_services s JOIN subdomains d ON d.id=s.subdomain_id
		WHERE s.target_id=? AND LOWER(d.subdomain)=?
		  AND COALESCE(s.status_code,0) BETWEEN 100 AND 599
		ORDER BY CASE WHEN LOWER(s.url) LIKE 'https://%' THEN 0 ELSE 1 END, s.url LIMIT 1`, targetID, wanted)); err == nil {
		return h
	}

	rows, err := db.QueryContext(ctx, selectCols+`
		FROM http_services s WHERE s.target_id=? AND COALESCE(s.status_code,0) BETWEEN 100 AND 599
		  AND INSTR(LOWER(s.url), ?) > 0
		ORDER BY CASE WHEN LOWER(s.url) LIKE 'https://%' THEN 0 ELSE 1 END, s.url LIMIT 200`, targetID, wanted)
	if err != nil {
		return watchHTTPSnapshot{}
	}
	defer rows.Close()
	for rows.Next() {
		h, err := scanWatchService(rows)
		if err != nil {
			continue
		}
		if normalizeWatchedHost(scanner.URLHost(h.URL)) == wanted {
			return h
		}
	}
	return watchHTTPSnapshot{}
}

func watchTechList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func scoreWatchCandidate(svc watchHTTPSnapshot, inScope bool) int {
	score := 0
	if svc.StatusCode >= 200 && svc.StatusCode < 300 {
		score += 4
	} else if svc.StatusCode > 0 {
		score++
	}
	if strings.TrimSpace(svc.Title) != "" {
		score += 2
	}
	if strings.TrimSpace(svc.Server) != "" {
		score++
	}
	if strings.TrimSpace(svc.Technologies) != "" {
		score++
	}
	if inScope {
		score += 2
	}
	return score
}

func newHostSeverity(status int) string {
	if status >= 200 && status < 300 {
		return "medium"
	}
	return "low"
}

func watchFingerprint(svc watchHTTPSnapshot) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%d|%s", svc.StatusCode, svc.Title,
		len(svc.Title), svc.Server)))
	return hex.EncodeToString(sum[:])
}
