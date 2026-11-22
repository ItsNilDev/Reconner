package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
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
}

type watchHTTPSnapshot struct {
	URL          string
	StatusCode   int
	Title        string
	Server       string
	Technologies string
	RedirectURL  string
}

func snapshotWatchHTTP(ctx context.Context, db *database.DB, targetID string) (map[string]watchHTTPSnapshot, error) {
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(url,''), COALESCE(status_code,0),
		COALESCE(title,''), COALESCE(server,''), COALESCE(technologies,'[]'), COALESCE(redirect_url,'')
		FROM http_services WHERE target_id=? ORDER BY url LIMIT 5000`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]watchHTTPSnapshot)
	for rows.Next() {
		var h watchHTTPSnapshot
		var technologies string
		if err := rows.Scan(&h.URL, &h.StatusCode, &h.Title, &h.Server, &technologies, &h.RedirectURL); err != nil {
			return nil, err
		}
		h.Technologies = joinWatchTechnologies(technologies)
		out[h.URL] = h
	}
	return out, rows.Err()
}

func joinWatchTechnologies(raw string) string {
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err == nil {
		sort.Strings(list)
		return strings.Join(list, ", ")
	}
	return strings.Trim(raw, "[]\"")
}

func watchStatusSeverity(oldCode, newCode int) string {
	old2xx := oldCode >= 200 && oldCode < 300
	new2xx := newCode >= 200 && newCode < 300
	if old2xx != new2xx {
		return "medium"
	}
	if (oldCode >= 300 && oldCode < 400) && newCode >= 500 {
		return "medium"
	}
	return "low"
}

func watchURLHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	trimmed := raw
	if i := strings.Index(trimmed, "://"); i >= 0 {
		trimmed = trimmed[i+3:]
	}
	if i := strings.IndexAny(trimmed, "/:@?"); i >= 0 {
		trimmed = trimmed[:i]
	}
	return strings.ToLower(trimmed)
}

// diffWatchHTTP now produces only detail-tier changes. New and removed HTTP
// services are state: the host emitter owns the one new_subdomain event for a
// newly online host, and removal is inferred from liveness state.
func diffWatchHTTP(before, after map[string]watchHTTPSnapshot, _ bool, _ bool) []watchChange {
	changes := make([]watchChange, 0)
	for raw, cur := range after {
		old, existed := before[raw]
		if !existed {
			continue
		}
		if old.StatusCode != cur.StatusCode {
			changes = append(changes, watchChange{
				URL: raw, ChangeType: "status_change",
				OldValue: fmt.Sprintf("status=%d title=%s", old.StatusCode, old.Title),
				NewValue: fmt.Sprintf("status=%d title=%s", cur.StatusCode, cur.Title),
				Severity: watchStatusSeverity(old.StatusCode, cur.StatusCode),
				Metadata: fmt.Sprintf(`{"old_code":%d,"new_code":%d}`, old.StatusCode, cur.StatusCode),
			})
		}
		if old.Title != cur.Title {
			changes = append(changes, watchChange{
				URL: raw, ChangeType: "page_change", OldValue: old.Title,
				NewValue: cur.Title, Severity: "low", Metadata: "{}",
			})
		}
		if old.Server != cur.Server || old.Technologies != cur.Technologies {
			changes = append(changes, watchChange{
				URL: raw, ChangeType: "tech_change",
				OldValue: fmt.Sprintf("Server: %s | Tech: %s", old.Server, old.Technologies),
				NewValue: fmt.Sprintf("Server: %s | Tech: %s", cur.Server, cur.Technologies),
				Severity: "low", Metadata: "{}",
			})
		}
		if old.RedirectURL != cur.RedirectURL {
			changes = append(changes, watchChange{
				URL: raw, ChangeType: "redirect_change", OldValue: old.RedirectURL,
				NewValue: cur.RedirectURL, Severity: "low", Metadata: "{}",
			})
		}
	}
	return changes
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
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tasks
		WHERE target_id=? AND type=? AND status='finished' AND id<>?`,
		targetID, watchScanType, taskID).Scan(&finished)
	if finished == 0 {
		s.baselineWatchHosts(ctx, targetID)
		return nil
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
		if err := rows.Scan(&c.host, &c.firstSeen, &c.firstAlive, &c.programID, &c.assetID, &alive); err == nil {
			c.alive = alive == 1
			raw = append(raw, c)
		}
	}
	rows.Close()

	candidates := make([]watchHostCandidate, 0, len(raw))
	for _, c := range raw {
		if !c.alive {
			continue
		}
		inScope, programID, assetID := scanner.IsWatchScopeHostEligible(ctx, s.db, targetID, c.host)
		if !inScope {
			programID, assetID = c.programID, c.assetID
		}
		svc := watchHTTPServiceForHost(ctx, s.db, targetID, c.host)
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
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Host < candidates[j].Host
	})

	// Fold identical responses into one event. The representative carries the
	// probed URL; fleet metadata carries every host in the group.
	groups := make([]watchHostCandidate, 0, len(candidates))
	members := make(map[string][]string, len(candidates))
	byFP := map[string]int{}
	for _, c := range candidates {
		if idx, ok := byFP[c.Fingerprint]; ok {
			members[c.Fingerprint] = append(members[c.Fingerprint], c.Host)
			if !groups[idx].InScope && c.InScope {
				groups[idx].InScope = true
				groups[idx].ProgramID = c.ProgramID
				groups[idx].AssetID = c.AssetID
			}
			continue
		}
		byFP[c.Fingerprint] = len(groups)
		groups = append(groups, c)
		members[c.Fingerprint] = []string{c.Host}
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
		hosts := members[g.Fingerprint]
		meta := map[string]any{
			"host": g.Host, "hosts": hosts, "fleet.size": len(hosts),
			"status": g.Service.StatusCode, "title": g.Service.Title,
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
			all = append(all, members[g.Fingerprint]...)
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
	if _, err := tx.ExecContext(ctx, `UPDATE watch_hosts SET announced_at=CURRENT_TIMESTAMP
		WHERE target_id=? AND announced_at IS NULL AND first_alive_at IS NOT NULL`, targetID); err != nil {
		s.logger.Warn("watch new-host: marker update failed", "error", err)
		return nil
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
	notifyHosts := make([]string, 0, len(visible))
	for _, g := range visible {
		if g.InScope {
			notifyHosts = append(notifyHosts, g.Host)
		}
	}
	if len(notifyHosts) > 0 {
		var domain string
		_ = s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
		summary := fmt.Sprintf("%d new host(s) up on %s", len(notifyHosts), domain)
		s.insertNotification(targetID, "new_host", "New hosts up", summary, "info")
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

func watchHTTPServiceForHost(ctx context.Context, db *database.DB, targetID, host string) watchHTTPSnapshot {
	var h watchHTTPSnapshot
	var tech string
	err := db.QueryRowContext(ctx, `SELECT COALESCE(url,''),COALESCE(status_code,0),COALESCE(title,''),
		COALESCE(server,''),COALESCE(technologies,'[]'),COALESCE(redirect_url,'')
		FROM http_services WHERE target_id=? AND (url LIKE 'https://'||?||'%' OR url LIKE 'http://'||?||'%')
		ORDER BY url LIMIT 1`, targetID, host, host).Scan(&h.URL, &h.StatusCode, &h.Title, &h.Server, &tech, &h.RedirectURL)
	if err != nil {
		return h
	}
	h.Technologies = joinWatchTechnologies(tech)
	return h
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

func (s *Scheduler) insertWatchRoundChanges(ctx context.Context, taskID, targetID string, changes []watchChange) {
	if len(changes) == 0 {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Warn("watch changes: begin failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO watch_round_changes
		(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`)
	if err != nil {
		s.logger.Warn("watch changes: prepare failed", "error", err)
		return
	}
	defer func() { _ = stmt.Close() }()

	written := 0
	for _, c := range changes {
		metadata := c.Metadata
		if metadata == "" {
			metadata = "{}"
		}
		if _, err := stmt.ExecContext(ctx, uuid.New().String(), targetID, taskID, c.URL,
			c.ChangeType, c.OldValue, c.NewValue, c.Severity, metadata); err != nil {
			s.logger.Warn("watch changes: insert failed", "error", err, "type", c.ChangeType)
			continue
		}
		written++
	}
	if err := tx.Commit(); err != nil {
		s.logger.Warn("watch changes: commit failed", "error", err)
		return
	}
	if written != len(changes) {
		s.logger.Warn("watch changes: some rows were not written", "written", written, "total", len(changes))
	}
	if s.hub != nil {
		s.hub.Broadcast("changes_written", map[string]any{"target_id": targetID, "count": written})
	}
}
