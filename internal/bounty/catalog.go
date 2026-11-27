package bounty

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	assetutil "github.com/recon-platform/internal/assets"
)

type ListOptions struct {
	Search         string
	Provider       string
	Status         string
	ProgramType    string
	Industry       string
	SafeHarbor     string
	AssetType      string
	OffersBounties *bool
	HasWildcard    *bool
	MinAssets      int
	MaxAssets      int
	MinRewardCents int
	Sort           string
	Page           int
	Limit          int
}

type ListResult struct {
	Programs    []Program         `json:"programs"`
	Total       int               `json:"total"`
	Page        int               `json:"page"`
	Limit       int               `json:"limit"`
	DetailIndex DetailIndexStatus `json:"detail_index"`
}

const programColumns = `p.id,p.provider,p.external_id,p.handle,p.name,p.url,p.logo_url,p.description,p.status,p.program_type,p.industry,
	p.offers_bounties,p.open_scope,p.safe_harbor,p.asset_count,p.in_scope_count,p.wildcard_count,p.scope_rank,
	p.min_reward_cents,p.max_reward_cents,p.currency,p.started_at,p.published_at,p.provider_updated_at,p.last_synced_at,p.detail_synced_at,p.scope_hash`

func scanProgram(scanner interface{ Scan(...any) error }) (Program, error) {
	var p Program
	var bounty, open int
	var started, published, providerUpdated, lastSync, detail sql.NullTime
	err := scanner.Scan(&p.ID, &p.Provider, &p.ExternalID, &p.Handle, &p.Name, &p.URL, &p.LogoURL, &p.Description, &p.Status, &p.ProgramType, &p.Industry,
		&bounty, &open, &p.SafeHarbor, &p.AssetCount, &p.InScopeCount, &p.WildcardCount, &p.ScopeRank, &p.MinRewardCents, &p.MaxRewardCents, &p.Currency,
		&started, &published, &providerUpdated, &lastSync, &detail, &p.ScopeHash)
	if err != nil {
		return p, err
	}
	p.OffersBounties = bounty == 1
	p.OpenScope = open == 1
	if started.Valid {
		p.StartedAt = &started.Time
	}
	if published.Valid {
		p.PublishedAt = &published.Time
	}
	if providerUpdated.Valid {
		p.ProviderUpdatedAt = &providerUpdated.Time
	}
	if lastSync.Valid {
		p.LastSyncedAt = &lastSync.Time
	}
	if detail.Valid {
		p.DetailSyncedAt = &detail.Time
		p.DetailsLoaded = true
	}
	return p, nil
}

func (s *Service) ListPrograms(ctx context.Context, o ListOptions) (ListResult, error) {
	detailIndex := s.DetailIndexStatus()
	// Scope-derived filters cannot be correct while provider details are still
	// lazy. Start a bounded background index automatically; callers receive
	// progress and can refresh without opening every program by hand.
	if o.HasWildcard != nil || o.AssetType != "" || o.MinAssets > 0 || o.MaxAssets > 0 || o.Sort == "assets_desc" || o.Sort == "assets_asc" || o.Sort == "wildcards" {
		detailIndex = s.StartDetailIndex()
	}
	if o.Page < 1 {
		o.Page = 1
	}
	if o.Limit < 1 {
		o.Limit = 30
	}
	if o.Limit > 100 {
		o.Limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	add := func(cond string, arg any) { where = append(where, cond); args = append(args, arg) }
	if q := strings.TrimSpace(o.Search); q != "" {
		where = append(where, "(p.name LIKE ? OR p.handle LIKE ? OR p.description LIKE ? OR p.industry LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	if o.Provider != "" {
		add("p.provider=?", o.Provider)
	}
	if o.Status != "" {
		add("p.status=?", o.Status)
	}
	if o.ProgramType != "" {
		add("p.program_type=?", o.ProgramType)
	}
	if o.Industry != "" {
		add("p.industry=?", o.Industry)
	}
	if o.SafeHarbor != "" {
		add("p.safe_harbor=?", o.SafeHarbor)
	}
	if o.OffersBounties != nil {
		add("p.offers_bounties=?", boolInt(*o.OffersBounties))
	}
	if o.HasWildcard != nil {
		if *o.HasWildcard {
			where = append(where, "p.wildcard_count>0")
		} else {
			// An unloaded program is unknown, not a confirmed non-wildcard.
			where = append(where, "p.detail_synced_at IS NOT NULL AND p.wildcard_count=0")
		}
	}
	if o.MinAssets > 0 {
		add("p.in_scope_count>=?", o.MinAssets)
	}
	if o.MaxAssets > 0 {
		where = append(where, "p.detail_synced_at IS NOT NULL")
		add("p.in_scope_count<=?", o.MaxAssets)
	}
	if o.MinRewardCents > 0 {
		add("p.max_reward_cents>=?", o.MinRewardCents)
	}
	if o.AssetType != "" {
		add("EXISTS(SELECT 1 FROM bounty_program_assets a WHERE a.program_id=p.id AND a.active=1 AND a.in_scope=1 AND a.eligible_submission=1 AND a.asset_type=?)", o.AssetType)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bounty_programs p WHERE "+clause, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}
	order := map[string]string{"newest": "COALESCE(p.started_at,p.published_at,p.last_synced_at) DESC", "updated": "COALESCE(p.provider_updated_at,p.detail_synced_at,p.last_synced_at) DESC", "assets_desc": "p.in_scope_count DESC,p.name", "assets_asc": "p.in_scope_count ASC,p.name", "reward_desc": "p.max_reward_cents DESC,p.name", "name": "p.name COLLATE NOCASE ASC", "wildcards": "p.wildcard_count DESC,p.in_scope_count DESC"}[o.Sort]
	if order == "" {
		order = "COALESCE(p.started_at,p.published_at,p.last_synced_at) DESC"
	}
	query := "SELECT " + programColumns + " FROM bounty_programs p WHERE " + clause + " ORDER BY " + order + " LIMIT ? OFFSET ?"
	args = append(args, o.Limit, (o.Page-1)*o.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	items := make([]Program, 0, o.Limit)
	for rows.Next() {
		p, err := scanProgram(rows)
		if err != nil {
			return ListResult{}, err
		}
		items = append(items, p)
	}
	return ListResult{Programs: items, Total: total, Page: o.Page, Limit: o.Limit, DetailIndex: detailIndex}, rows.Err()
}

func (s *Service) GetProgram(ctx context.Context, id string) (Program, error) {
	detailErr := s.EnsureDetails(ctx, id)
	p, err := scanProgram(s.db.QueryRowContext(ctx, "SELECT "+programColumns+" FROM bounty_programs p WHERE p.id=?", id))
	if err != nil {
		return p, err
	}
	if detailErr != nil && !p.DetailsLoaded {
		return p, detailErr
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,program_id,external_id,identifier,asset_type,category,is_wildcard,in_scope,
		eligible_submission,eligible_bounty,max_severity,instruction,reward_json,metadata,active,provider_created_at,provider_updated_at,raw_hash
		FROM bounty_program_assets WHERE program_id=? ORDER BY in_scope DESC,eligible_submission DESC,identifier COLLATE NOCASE`, id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	p.Assets = []Asset{}
	for rows.Next() {
		var a Asset
		var wildcard, inScope, submission, bounty, active int
		var rewardJSON, metadataJSON string
		var created, updated sql.NullTime
		if err := rows.Scan(&a.ID, &a.ProgramID, &a.ExternalID, &a.Identifier, &a.AssetType, &a.Category, &wildcard, &inScope, &submission, &bounty, &a.MaxSeverity, &a.Instruction, &rewardJSON, &metadataJSON, &active, &created, &updated, &a.RawHash); err != nil {
			return p, err
		}
		a.IsWildcard = wildcard == 1
		a.InScope = inScope == 1
		a.EligibleSubmission = submission == 1
		a.EligibleBounty = bounty == 1
		a.Active = active == 1
		if created.Valid {
			a.ProviderCreatedAt = &created.Time
		}
		if updated.Valid {
			a.ProviderUpdatedAt = &updated.Time
		}
		_ = json.Unmarshal([]byte(rewardJSON), &a.Reward)
		_ = json.Unmarshal([]byte(metadataJSON), &a.Metadata)
		p.Assets = append(p.Assets, a)
	}
	return p, rows.Err()
}

type CreateProjectRequest struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	Priority             string   `json:"priority"`
	Notes                string   `json:"notes"`
	AssetIDs             []string `json:"asset_ids"`
	MonitorEnabled       bool     `json:"monitor_enabled"`
	MonitorIntervalHours int      `json:"monitor_interval_hours"`
	// WatchOnly creates a BREADTH project: it runs the cheap watch rounds
	// (passive discovery + one HTTP probe) instead of the deep pipeline.
	// The backend is the enforcement point — network/IP assets are filtered
	// out so the project can never end up mixed, and the old monitor tier is
	// switched off (both flags on would double-scan the project).
	WatchOnly bool `json:"watch_only"`
}

func projectAssetKind(t string) string {
	switch t {
	case "cidr", "ip":
		return "network"
	case "domain", "wildcard", "url", "page", "js", "api":
		return "web"
	case "app_store", "android", "ios", "hardware", "source_code", "other", "reference":
		return "reference"
	default:
		return "reference"
	}
}

// managedAssetKind also demotes web-typed assets whose identifier is not a
// host or URL. Old catalog rows can carry a prose note with type "domain";
// those values must never become project roots.
func managedAssetKind(a Asset) string {
	kind := projectAssetKind(a.AssetType)
	if kind != "web" {
		return kind
	}
	if !assetutil.IsScannableWebAsset(a.AssetType, a.Identifier) {
		return "reference"
	}
	return "web"
}

func (s *Service) CreateProject(ctx context.Context, ownerID int64, programID string, req CreateProjectRequest) (string, error) {
	p, err := s.GetProgram(ctx, programID)
	if err != nil {
		return "", err
	}
	return s.createProjectFromProgram(ctx, ownerID, p, req)
}

// createProjectFromProgram holds the import logic so a bulk import can reuse a
// program that was already loaded. That avoids a second provider detail fetch
// for every program in the batch.
func (s *Service) createProjectFromProgram(ctx context.Context, ownerID int64, p Program, req CreateProjectRequest) (string, error) {
	if len(req.AssetIDs) == 0 {
		return "", fmt.Errorf("select at least one current scope asset")
	}
	selected := map[string]bool{}
	for _, id := range req.AssetIDs {
		selected[id] = true
	}
	assets := []Asset{}
	for _, a := range p.Assets {
		if !a.Active || !a.InScope || !a.EligibleSubmission {
			continue
		}
		if len(selected) > 0 && !selected[a.ID] {
			continue
		}
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		return "", fmt.Errorf("select at least one active, submission-eligible asset")
	}
	if len(assets) != len(selected) {
		return "", fmt.Errorf("one or more selected assets are missing or no longer submission-eligible; refresh the program scope")
	}
	values := make([]string, 0, len(assets))
	hasWeb, hasNet := false, false
	skippedNetwork := []string{}
	skippedAppStore := []string{}
	for _, a := range assets {
		if a.AssetType == "app_store" || assetutil.IsAppStoreAsset(a.Identifier) {
			skippedAppStore = append(skippedAppStore, a.Identifier)
			continue
		}
		kind := managedAssetKind(a)
		if kind == "reference" {
			continue
		}
		// A breadth project runs WEB modules only. Network assets (CIDR/IP) have
		// no place in a watch round, and a mixed project cannot run one at all —
		// so the backend drops them here instead of creating a broken project.
		if req.WatchOnly && kind == "network" {
			skippedNetwork = append(skippedNetwork, a.Identifier)
			continue
		}
		values = append(values, a.Identifier)
		if kind == "network" {
			hasNet = true
		} else {
			hasWeb = true
		}
	}
	if req.WatchOnly && len(values) == 0 {
		return "", fmt.Errorf("no web assets: a breadth project needs at least one web asset")
	}
	if len(skippedNetwork) > 0 && s.log != nil {
		s.log.Info("Breadth project import dropped network assets", "count", len(skippedNetwork), "assets", strings.Join(skippedNetwork, ", "))
	}
	if len(skippedAppStore) > 0 && s.log != nil {
		s.log.Info("Project import dropped app-store assets", "count", len(skippedAppStore), "assets", strings.Join(skippedAppStore, ", "))
	}
	if len(values) == 0 {
		values = []string{p.Provider + ":" + p.Handle}
	}
	kind := "web"
	if hasNet && !hasWeb {
		kind = "network"
	} else if hasNet && hasWeb {
		kind = "mixed"
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = p.Name
	}
	priority := strings.TrimSpace(req.Priority)
	if priority == "" {
		priority = "medium"
	}
	hours := req.MonitorIntervalHours
	if hours < 1 {
		hours = 12
	}
	scope := strings.Join(values, ",")
	targetID := uuid.New().String()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// A breadth project starts in the watch tier: the old monitor tier is off
	// (both flags on would scan the project twice) and the first watch round is
	// due immediately.
	monitorEnabled := req.MonitorEnabled
	watchOnly := 0
	if req.WatchOnly {
		monitorEnabled = false
		watchOnly = 1
	}
	// watch_next_run must be a real SQLite timestamp, not a bound string: the
	// due query compares watch_next_run <= datetime('now') as TEXT, and the
	// literal "CURRENT_TIMESTAMP" sorts after "2026-..." so the first round
	// would never be due. Newly created breadth projects start due immediately
	// with watch_stagger_pending = 1 so steady-state rounds stagger after Round 1.
	// Deep projects keep NULL ("not scheduled") and watch_stagger_pending = 0.
	_, err = tx.ExecContext(ctx, `INSERT INTO targets(id,domain,name,description,priority,notes,kind,exclude_scope,owner_id,monitor_enabled,monitor_interval_hours,watch_only,watch_next_run,watch_paused,watch_fail_count,watch_root_index,watch_stagger_pending)
		VALUES(?,?,?,?,?,?,?,'',?,?,?,?,CASE WHEN ? = 1 THEN datetime('now') ELSE NULL END,0,0,0,?)`, targetID, scope, name, req.Description, priority, req.Notes, kind, ownerID, boolInt(monitorEnabled), hours, watchOnly, watchOnly, watchOnly)
	if err != nil {
		return "", err
	}
	for _, pattern := range programDenyRules(p) {
		if _, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO target_exclusions(id,target_id,source,program_id,pattern) VALUES(?,?,'bounty',?,?)`,
			uuid.New().String(), targetID, p.ID, pattern,
		); err != nil {
			return "", err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO project_programs(target_id,program_id,auto_sync,last_scope_hash,last_checked_at) VALUES(?,?,1,?,CURRENT_TIMESTAMP)`, targetID, p.ID, p.ScopeHash)
	if err != nil {
		return "", err
	}
	for _, a := range assets {
		if req.WatchOnly && managedAssetKind(a) == "network" {
			continue // network assets are not part of a breadth project
		}
		if managedAssetKind(a) == "reference" {
			continue // prose notes and app listings are not project assets
		}
		meta, _ := json.Marshal(map[string]any{"provider": p.Provider, "program": p.Handle, "raw_hash": a.RawHash, "eligible_bounty": a.EligibleBounty, "max_severity": a.MaxSeverity, "instruction": a.Instruction})
		assetMonitor := 1
		if req.WatchOnly {
			assetMonitor = 0 // the old monitor tier is off for breadth projects
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at)
		VALUES(?,?,?,?,?,?,?,?, 'approved',?,?,CURRENT_TIMESTAMP)`, uuid.New().String(), targetID, a.Identifier, a.Identifier, managedAssetKind(a), a.AssetType, "bounty:"+p.Provider, a.ID, assetMonitor, string(meta))
		if err != nil {
			return "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return targetID, nil
}

// maxBulkProjectCreations bounds one bulk request. Program detail fetches can
// reach providers, so an unbounded list could tie up the API for a long time.
const maxBulkProjectCreations = 100

type BulkCreateProjectsRequest struct {
	ProgramIDs           []string `json:"program_ids"`
	Coverage             string   `json:"coverage"`     // breadth or deep
	AssetPolicy          string   `json:"asset_policy"` // all_eligible_web or all_eligible
	Priority             string   `json:"priority"`
	NameTemplate         string   `json:"name_template"` // {program}, {handle}, {provider}
	MonitorEnabled       bool     `json:"monitor_enabled"`
	MonitorIntervalHours int      `json:"monitor_interval_hours"`
	SkipExisting         bool     `json:"skip_existing"`
}

type BulkCreateProjectResult struct {
	ProgramID       string `json:"program_id"`
	ProgramName     string `json:"program_name,omitempty"`
	OK              bool   `json:"ok"`
	TargetID        string `json:"target_id,omitempty"`
	Assets          int    `json:"assets,omitempty"`
	SkippedNetwork  int    `json:"skipped_network,omitempty"`
	SkippedAppStore int    `json:"skipped_app_store,omitempty"`
	SkippedInvalid  int    `json:"skipped_invalid,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// CreateProjectsBulk imports many bounty programs in one call. Each program is
// independent: one failure never rolls back the others. The caller gets one
// result per program so the UI can show created, skipped and failed projects.
func (s *Service) CreateProjectsBulk(ctx context.Context, ownerID int64, req BulkCreateProjectsRequest) ([]BulkCreateProjectResult, error) {
	ids := make([]string, 0, len(req.ProgramIDs))
	seen := map[string]bool{}
	for _, raw := range req.ProgramIDs {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("select at least one program")
	}
	if len(ids) > maxBulkProjectCreations {
		return nil, fmt.Errorf("bulk import is limited to %d programs", maxBulkProjectCreations)
	}

	coverage := strings.ToLower(strings.TrimSpace(req.Coverage))
	if coverage == "" {
		coverage = "breadth"
	}
	if coverage != "breadth" && coverage != "deep" {
		return nil, fmt.Errorf("coverage must be breadth or deep")
	}
	assetPolicy := strings.ToLower(strings.TrimSpace(req.AssetPolicy))
	if assetPolicy == "" {
		assetPolicy = "all_eligible_web"
	}
	if assetPolicy != "all_eligible_web" && assetPolicy != "all_eligible" {
		return nil, fmt.Errorf("asset_policy must be all_eligible_web or all_eligible")
	}

	results := make([]BulkCreateProjectResult, 0, len(ids))
	for _, programID := range ids {
		result := BulkCreateProjectResult{ProgramID: programID}
		p, err := s.GetProgram(ctx, programID)
		if err != nil {
			result.Reason = "program unavailable"
			results = append(results, result)
			continue
		}
		result.ProgramName = p.Name

		if req.SkipExisting {
			var existingID string
			err := s.db.QueryRowContext(ctx, `
				SELECT t.id FROM project_programs pp
				JOIN targets t ON t.id = pp.target_id
				WHERE pp.program_id = ? AND t.owner_id = ? LIMIT 1`, programID, ownerID).Scan(&existingID)
			if err == nil {
				result.Reason = "already_linked"
				result.TargetID = existingID
				results = append(results, result)
				continue
			}
			if err != sql.ErrNoRows {
				result.Reason = "lookup failed"
				results = append(results, result)
				continue
			}
		}

		assetIDs := []string{}
		skippedNetwork := 0
		skippedAppStore := 0
		skippedInvalid := 0
		for _, a := range p.Assets {
			if !a.Active || !a.InScope || !a.EligibleSubmission {
				continue
			}
			if a.AssetType == "app_store" || assetutil.IsAppStoreAsset(a.Identifier) {
				skippedAppStore++
				continue
			}
			kind := managedAssetKind(a)
			if kind == "reference" {
				if projectAssetKind(a.AssetType) == "web" {
					skippedInvalid++
				}
				continue
			}
			if kind == "network" {
				if coverage == "breadth" || assetPolicy == "all_eligible_web" {
					skippedNetwork++
					continue
				}
			}
			assetIDs = append(assetIDs, a.ID)
		}
		if len(assetIDs) == 0 {
			result.Reason = "no eligible web assets"
			results = append(results, result)
			continue
		}

		name := p.Name
		if strings.TrimSpace(req.NameTemplate) != "" {
			name = strings.NewReplacer(
				"{program}", p.Name,
				"{handle}", p.Handle,
				"{provider}", p.Provider,
			).Replace(req.NameTemplate)
		}
		notes := ""
		if p.URL != "" {
			notes = "Program: " + p.URL
		}
		createReq := CreateProjectRequest{
			Name:                 name,
			Description:          "Bulk import from " + p.Provider + " public program",
			Priority:             req.Priority,
			Notes:                notes,
			AssetIDs:             assetIDs,
			MonitorEnabled:       req.MonitorEnabled && coverage == "deep",
			MonitorIntervalHours: req.MonitorIntervalHours,
			WatchOnly:            coverage == "breadth",
		}
		targetID, err := s.createProjectFromProgram(ctx, ownerID, p, createReq)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				result.Reason = "already_linked"
			} else {
				result.Reason = err.Error()
			}
			results = append(results, result)
			continue
		}
		result.OK = true
		result.TargetID = targetID
		result.Assets = len(assetIDs)
		result.SkippedNetwork = skippedNetwork
		result.SkippedAppStore = skippedAppStore
		result.SkippedInvalid = skippedInvalid
		results = append(results, result)
	}
	return results, nil
}

type ScopeEvent struct {
	ID             string     `json:"id"`
	TargetID       string     `json:"target_id"`
	ProgramID      string     `json:"program_id"`
	ProgramAssetID string     `json:"program_asset_id"`
	EventType      string     `json:"event_type"`
	Identifier     string     `json:"identifier"`
	OldJSON        string     `json:"old_json"`
	NewJSON        string     `json:"new_json"`
	Status         string     `json:"status"`
	DetectedAt     time.Time  `json:"detected_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

func (s *Service) ListScopeEvents(ctx context.Context, targetID string) ([]ScopeEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,e.target_id,e.program_id,COALESCE(e.program_asset_id,''),e.event_type,e.identifier,e.old_json,e.new_json,e.status,e.detected_at,e.resolved_at,
		COALESCE(b.asset_type,''),COALESCE(b.identifier,'')
		FROM bounty_scope_events e
		LEFT JOIN bounty_program_assets b ON b.id = e.program_asset_id
		WHERE e.target_id=? ORDER BY e.detected_at DESC`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeEvent{}
	for rows.Next() {
		var e ScopeEvent
		var resolved sql.NullTime
		var assetType, assetIdentifier string
		if err := rows.Scan(&e.ID, &e.TargetID, &e.ProgramID, &e.ProgramAssetID, &e.EventType, &e.Identifier, &e.OldJSON, &e.NewJSON, &e.Status, &e.DetectedAt, &resolved, &assetType, &assetIdentifier); err != nil {
			return nil, err
		}
		// Hide old events for app listings and prose notes. Keep events whose
		// program asset no longer exists; those are genuine history.
		if e.ProgramAssetID != "" && !assetutil.IsTrackableScopeAsset(assetType, assetIdentifier) {
			continue
		}
		if resolved.Valid {
			e.ResolvedAt = &resolved.Time
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) reconcileLinkedProjects(ctx context.Context, programID string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id FROM project_programs WHERE program_id=? AND auto_sync=1`, programID)
	if err != nil {
		return err
	}
	targets := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			targets = append(targets, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	// Release the read cursor before reconciliation starts writes. This matters
	// when SQLite is configured with a small connection pool and avoids holding a
	// reader open across GetProgram/UPDATE calls.
	if err := rows.Close(); err != nil {
		return err
	}
	for _, targetID := range targets {
		if err := s.reconcileProject(ctx, targetID, programID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileProject(ctx context.Context, targetID, programID string) error {
	p, err := s.GetProgram(ctx, programID)
	if err != nil {
		return err
	}
	// JSON keeps the old state in the same bounty.Asset shape as new_json, so
	// reviewers see one consistent diff structure for modified events.
	existing := map[string]struct{ ID, Value, Status, Raw, JSON string }{}
	staleNonWeb := []string{}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.source_id,a.value,a.approval_status,a.metadata,
		COALESCE(b.asset_type,''),COALESCE(b.identifier,'')
		FROM assets a JOIN bounty_program_assets b ON b.id=a.source_id
		WHERE a.target_id=? AND b.program_id=? AND a.source LIKE 'bounty:%'`, targetID, programID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, sid, value, status, meta, bType, bIdentifier string
		if rows.Scan(&id, &sid, &value, &status, &meta, &bType, &bIdentifier) == nil {
			if !assetutil.IsTrackableScopeAsset(bType, bIdentifier) {
				// Old imports may have approved an app listing or a prose note.
				// Suspend it silently. No event and no bell row for this cleanup.
				if status == "approved" {
					staleNonWeb = append(staleNonWeb, id)
				}
				continue
			}
			var m map[string]any
			_ = json.Unmarshal([]byte(meta), &m)
			raw, _ := m["raw_hash"].(string)
			oldAsset := Asset{
				ID: sid, Identifier: value, AssetType: bType, RawHash: raw,
				ProgramID: programID, Active: true, InScope: true, EligibleSubmission: true,
				IsWildcard: strings.HasPrefix(value, "*."),
			}
			if v, ok := m["eligible_bounty"].(bool); ok {
				oldAsset.EligibleBounty = v
			}
			if v, ok := m["max_severity"].(string); ok {
				oldAsset.MaxSeverity = v
			}
			if v, ok := m["instruction"].(string); ok {
				oldAsset.Instruction = v
			}
			existing[sid] = struct{ ID, Value, Status, Raw, JSON string }{id, value, status, raw, mustJSON(oldAsset)}
		}
	}
	rows.Close()
	for _, id := range staleNonWeb {
		_, _ = s.db.ExecContext(ctx, `UPDATE assets SET approval_status='suspended',monitor_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	}
	current := map[string]Asset{}
	added, removed, modified := 0, 0, 0
	for _, a := range p.Assets {
		if !assetutil.IsTrackableScopeAsset(a.AssetType, a.Identifier) {
			continue
		}
		if a.Active && a.InScope && a.EligibleSubmission {
			current[a.ID] = a
			if old, ok := existing[a.ID]; !ok {
				// Carry the raw hash so approval can detect an upstream edit
				// made after this "added" event was recorded (A13).
				if s.createScopeEvent(ctx, targetID, p.ID, a.ID, "added", a.Identifier, "{}", mustJSON(a), a.RawHash) {
					added++
				}
			} else if old.Status == "suspended" {
				if _, err := s.db.ExecContext(ctx, `DELETE FROM bounty_scope_decisions
					WHERE target_id=? AND program_id=? AND program_asset_id=? AND event_type='added'`,
					targetID, p.ID, a.ID); err != nil {
					return err
				}
				if s.createScopeEvent(ctx, targetID, p.ID, a.ID, "added", a.Identifier, "{}", mustJSON(a), a.RawHash) {
					added++
				}
			} else if old.Raw != "" && old.Raw != a.RawHash {
				if s.createScopeEvent(ctx, targetID, p.ID, a.ID, "modified", a.Identifier, old.JSON, mustJSON(a), a.RawHash) {
					modified++
				}
			}
		}
	}
	for sid, old := range existing {
		if _, ok := current[sid]; !ok && old.Status != "suspended" {
			_, _ = s.db.ExecContext(ctx, `UPDATE assets SET approval_status='suspended',monitor_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?`, old.ID)
			if s.createScopeEvent(ctx, targetID, p.ID, sid, "removed", old.Value, old.JSON, "{}") {
				removed++
			}
		}
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE project_programs SET last_scope_hash=?,last_checked_at=CURRENT_TIMESTAMP WHERE target_id=? AND program_id=?`, p.ScopeHash, targetID, p.ID)
	// Refresh this program's typed deny rules in target_exclusions. Only rows
	// owned by (target_id, source='bounty', program_id) are reconciled; manual
	// rules and other programs' rules stay untouched.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	prevRows, err := tx.QueryContext(ctx, `SELECT pattern FROM target_exclusions WHERE target_id=? AND source='bounty' AND program_id=?`, targetID, programID)
	if err != nil {
		return err
	}
	previousRules := map[string]struct{}{}
	for prevRows.Next() {
		var pattern string
		if err := prevRows.Scan(&pattern); err != nil {
			prevRows.Close()
			return err
		}
		previousRules[pattern] = struct{}{}
	}
	if err := prevRows.Err(); err != nil {
		prevRows.Close()
		return err
	}
	prevRows.Close()

	newDenyRules := programDenyRules(p)
	currentRules := make(map[string]struct{}, len(newDenyRules))
	for _, pattern := range newDenyRules {
		currentRules[pattern] = struct{}{}
	}
	for pattern := range previousRules {
		if _, ok := currentRules[pattern]; !ok {
			if _, err := tx.ExecContext(ctx, `DELETE FROM target_exclusions WHERE target_id=? AND source='bounty' AND program_id=? AND pattern=?`, targetID, programID, pattern); err != nil {
				return err
			}
		}
	}
	for _, pattern := range newDenyRules {
		if _, ok := previousRules[pattern]; !ok {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO target_exclusions (id,target_id,source,program_id,pattern) VALUES (?,?,'bounty',?,?)`, uuid.New().String(), targetID, programID, pattern); err != nil {
				return err
			}
		}
	}
	// Commit the deny snapshot before recording rule events. createRuleEvent
	// writes through s.db on another connection; an open write transaction here
	// would block that insert until the SQLite busy timeout and drop the event.
	if err := tx.Commit(); err != nil {
		return err
	}

	// A deny rule can be added or withdrawn without any asset row. Record the
	// rule itself as an approved upstream event so Changes shows the real edit.
	ruleAdded, ruleRemoved := 0, 0
	for identifier := range previousRules {
		if _, ok := currentRules[identifier]; !ok {
			ruleJSON := mustJSON(map[string]any{"identifier": identifier, "rule": identifier, "in_scope": false})
			if s.createRuleEvent(ctx, targetID, p.ID, "rule_removed", identifier, ruleJSON, "{}") {
				ruleRemoved++
			}
		}
	}
	for _, identifier := range newDenyRules {
		if _, ok := previousRules[identifier]; !ok {
			ruleJSON := mustJSON(map[string]any{"identifier": identifier, "rule": identifier, "in_scope": false})
			if s.createRuleEvent(ctx, targetID, p.ID, "rule_added", identifier, "{}", ruleJSON) {
				ruleAdded++
			}
		}
	}
	if added+removed+modified+ruleAdded+ruleRemoved > 0 {
		body := fmt.Sprintf("%s scope changed: %d added, %d removed, %d modified, %d rules added, %d rules withdrawn. New assets require approval; removed assets were suspended.", p.Name, added, removed, modified, ruleAdded, ruleRemoved)
		if _, err := s.db.ExecContext(ctx, `INSERT INTO notifications(id,target_id,type,title,body,url,severity) VALUES(?,?,?,?,?,?,?)`, uuid.New().String(), targetID, "bounty_scope_change", "Bug bounty scope changed", body, "/targets/"+url.PathEscape(targetID), "medium"); err != nil {
			return err
		}
	}
	return nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// programDenyRules rebuilds the active out-of-scope rules a program contributes.
func programDenyRules(p Program) []string {
	seen := make(map[string]struct{}, len(p.Assets))
	out := make([]string, 0)
	for _, a := range p.Assets {
		identifier := strings.TrimSpace(a.Identifier)
		if !a.Active || (a.InScope && a.EligibleSubmission) || identifier == "" {
			continue
		}
		if _, dup := seen[identifier]; dup {
			continue
		}
		seen[identifier] = struct{}{}
		out = append(out, identifier)
	}
	return out
}

// createRuleEvent records an upstream deny-rule change with no approval step.
// A repeat sync of the same rule set must not add another event.
func (s *Service) createRuleEvent(ctx context.Context, targetID, programID, eventType, identifier, oldJSON, newJSON string) bool {
	// A repeat sync sees the same diff and must not add another event. A real
	// withdraw after a restore is a new edit, so compare with the latest event
	// for this identifier instead of any event in history.
	var latest string
	err := s.db.QueryRowContext(ctx, `SELECT event_type FROM bounty_scope_events
		WHERE target_id=? AND program_id=? AND identifier=?
		  AND event_type IN ('rule_added','rule_removed')
		ORDER BY detected_at DESC, rowid DESC LIMIT 1`,
		targetID, programID, identifier).Scan(&latest)
	if err == nil && latest == eventType {
		return false
	}
	eventID := uuid.New().String()
	_, err = s.db.ExecContext(ctx, `INSERT INTO bounty_scope_events
		(id,target_id,program_id,event_type,identifier,old_json,new_json,status,detected_at,resolved_at)
		VALUES(?,?,?,?,?,?,?,'approved',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		eventID, targetID, programID, eventType, identifier, oldJSON, newJSON)
	if err != nil {
		return false
	}
	if s.onScopeEvent != nil {
		s.onScopeEvent(ctx, targetID, programID, eventID, eventType, identifier)
	}
	return true
}

// scopeEventFingerprint identifies one specific scope state. "added" and
// "modified" events are keyed by the new program-asset state; "removed" events
// are keyed by the old state that was taken away. A rejected or approved
// decision on this fingerprint suppresses the same event on later syncs. A
// genuine later change produces a different JSON state and is reported again.
func scopeEventFingerprint(eventType, identifier, oldJSON, newJSON string) string {
	state := newJSON
	if eventType == "removed" {
		state = oldJSON
	}
	sum := sha256.Sum256([]byte(eventType + "\x00" + identifier + "\x00" + state))
	return hex.EncodeToString(sum[:])
}

// createScopeEvent inserts a pending review event unless the fingerprint was
// already decided or a pending event exists. It reports whether a row was
// inserted so callers count and notify only for genuinely new changes.
func (s *Service) createScopeEvent(ctx context.Context, targetID, programID, assetID, eventType, identifier, oldJSON, newJSON string, stateHash ...string) bool {
	fingerprint := scopeEventFingerprint(eventType, identifier, oldJSON, newJSON)
	// RawHash is hidden from the JSON payload, so a raw-only upstream edit would
	// otherwise produce the same fingerprint. Fold it in for modifications.
	if len(stateHash) > 0 && stateHash[0] != "" {
		fingerprint = scopeEventFingerprint(eventType, identifier, oldJSON, newJSON+"\x00"+stateHash[0])
	}
	var decided int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bounty_scope_decisions WHERE target_id=? AND program_id=? AND program_asset_id=? AND event_type=? AND fingerprint=?`, targetID, programID, assetID, eventType, fingerprint).Scan(&decided)
	if decided > 0 {
		return false
	}
	// A newer proposal supersedes an older pending one instead of being hidden
	// by it. The operator reviews the latest state only.
	var pendingID, pendingHash string
	if err := s.db.QueryRowContext(ctx, `SELECT id,COALESCE(proposed_hash,'') FROM bounty_scope_events
		WHERE target_id=? AND program_asset_id=? AND event_type=? AND status='pending'
		ORDER BY detected_at DESC LIMIT 1`, targetID, assetID, eventType).Scan(&pendingID, &pendingHash); err == nil {
		// A legacy pending row has no hash. Treat it as stale rather than let
		// it block every later edit forever (A13).
		if pendingHash != "" && pendingHash == fingerprint {
			return false
		}
		_, _ = s.db.ExecContext(ctx, `UPDATE bounty_scope_events SET status='superseded' WHERE id=?`, pendingID)
	}
	rawHash := ""
	if len(stateHash) > 0 {
		rawHash = stateHash[0]
	}
	eventID := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `INSERT INTO bounty_scope_events(id,target_id,program_id,program_asset_id,event_type,identifier,old_json,new_json,status,proposed_hash,proposed_raw_hash) VALUES(?,?,?,?,?,?,?,?, 'pending',?,?)`, eventID, targetID, programID, assetID, eventType, identifier, oldJSON, newJSON, fingerprint, rawHash)
	if err != nil {
		return false
	}
	if s.onScopeEvent != nil {
		s.onScopeEvent(ctx, targetID, programID, eventID, eventType, identifier)
	}
	return true
}

func (s *Service) ResolveScopeEvent(ctx context.Context, targetID, eventID, decision string) error {
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("decision must be approve or reject")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var eventType, assetID, status, programID, identifier, oldJSON, newJSON, proposedHash, proposedRawHash string
	err = tx.QueryRowContext(ctx, `SELECT event_type,COALESCE(program_asset_id,''),status,program_id,identifier,old_json,new_json,COALESCE(proposed_hash,''),COALESCE(proposed_raw_hash,'') FROM bounty_scope_events WHERE id=? AND target_id=?`, eventID, targetID).Scan(&eventType, &assetID, &status, &programID, &identifier, &oldJSON, &newJSON, &proposedHash, &proposedRawHash)
	if err != nil {
		return err
	}
	if status == "superseded" {
		return fmt.Errorf("scope event was superseded by a newer proposal")
	}
	if status != "pending" && status != "rejected" {
		return fmt.Errorf("scope event already resolved")
	}
	if status == "rejected" && decision == "reject" {
		return fmt.Errorf("scope event already dismissed")
	}
	if decision == "approve" {
		switch eventType {
		case "added", "modified":
			var a Asset
			var wild, inScope, submit, bounty, active int
			var reward, metadata string
			err = tx.QueryRowContext(ctx, `SELECT id,program_id,external_id,identifier,asset_type,category,is_wildcard,in_scope,eligible_submission,eligible_bounty,max_severity,instruction,reward_json,metadata,active,raw_hash FROM bounty_program_assets WHERE id=?`, assetID).Scan(&a.ID, &a.ProgramID, &a.ExternalID, &a.Identifier, &a.AssetType, &a.Category, &wild, &inScope, &submit, &bounty, &a.MaxSeverity, &a.Instruction, &reward, &metadata, &active, &a.RawHash)
			if err != nil {
				return err
			}
			if active != 1 || inScope != 1 || submit != 1 {
				return fmt.Errorf("scope asset is no longer active and submission-eligible")
			}
			var watchOnly int
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(watch_only,0) FROM targets WHERE id=?`, targetID).Scan(&watchOnly); err != nil {
				return err
			}
			if watchOnly == 1 && managedAssetKind(a) != "web" {
				return fmt.Errorf("cannot approve network asset on a breadth watch project; switch to deep coverage first")
			}
			// Refuse to apply a proposal against a different upstream state. A
			// later edit supersedes the pending row; approving the stale one
			// must not silently land the new state under the old decision key.
			if proposedRawHash != "" && proposedRawHash != a.RawHash {
				return fmt.Errorf("scope changed since this proposal; refresh the program and review the new event")
			}
			meta := map[string]any{"raw_hash": a.RawHash, "eligible_bounty": bounty == 1, "max_severity": a.MaxSeverity, "instruction": a.Instruction}
			metaJSON, _ := json.Marshal(meta)
			assetMonitorEnabled := 1
			if watchOnly == 1 {
				assetMonitorEnabled = 0
			}
			// The upsert must NOT rewrite a row the watch tier landed
			// (source='watch:scope'): that row is the operator's landed scope
			// and keeps its own source, asset_type and metadata. The WHERE on
			// the conflict clause leaves the landed row untouched.
			res, err := tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at) VALUES(?,?,?,?,?,?, 'bounty:catalog',?,'approved',?,?,CURRENT_TIMESTAMP) ON CONFLICT(target_id,value) DO UPDATE SET value=excluded.value,kind=excluded.kind,asset_type=excluded.asset_type,source='bounty:catalog',source_id=excluded.source_id,approval_status='approved',monitor_enabled=excluded.monitor_enabled,metadata=excluded.metadata,updated_at=CURRENT_TIMESTAMP WHERE assets.source <> 'watch:scope'`, uuid.New().String(), targetID, a.Identifier, a.Identifier, managedAssetKind(a), a.AssetType, a.ID, assetMonitorEnabled, string(metaJSON))
			if err != nil {
				return err
			}
			if affected, err := res.RowsAffected(); err != nil {
				return err
			} else if affected == 0 {
				if _, err := tx.ExecContext(ctx, `UPDATE assets SET source_id=?, asset_type=CASE WHEN asset_type='subdomain' THEN ? ELSE asset_type END, approval_status='approved', updated_at=CURRENT_TIMESTAMP WHERE target_id=? AND value=? AND source='watch:scope'`, a.ID, a.AssetType, targetID, a.Identifier); err != nil {
					return err
				}
			}
			if watchOnly == 1 && managedAssetKind(a) == "web" {
				if _, err := tx.ExecContext(ctx, `
					UPDATE targets
					SET watch_next_run = datetime('now'), updated_at = CURRENT_TIMESTAMP
					WHERE id = ?
					  AND COALESCE(watch_only, 0) = 1
					  AND COALESCE(watch_paused, 0) = 0
					  AND watch_next_run IS NOT NULL
					  AND watch_next_run > datetime('now')
				`, targetID); err != nil {
					return err
				}
			}
		case "removed":
			_, err = tx.ExecContext(ctx, `UPDATE assets SET approval_status='suspended',monitor_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE target_id=? AND source_id=?`, targetID, assetID)
			if err != nil {
				return err
			}
		}
	}
	fingerprint := proposedHash
	if fingerprint == "" {
		fingerprint = scopeEventFingerprint(eventType, identifier, oldJSON, newJSON)
	}
	// One decision per fingerprint. Upserting also lets an operator approve a
	// scope change they dismissed earlier: the approve path below still runs,
	// and the stored decision flips so the event cannot come back again.
	_, err = tx.ExecContext(ctx, `INSERT INTO bounty_scope_decisions
		(id,target_id,program_id,program_asset_id,event_type,identifier,fingerprint,decision,resolved_event_id)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id,program_id,program_asset_id,event_type,fingerprint)
		DO UPDATE SET decision=excluded.decision,resolved_event_id=excluded.resolved_event_id,decided_at=CURRENT_TIMESTAMP`,
		uuid.New().String(), targetID, programID, assetID, eventType, identifier, fingerprint, decision, eventID)
	if err != nil {
		return err
	}
	if decision == "approve" && eventType == "modified" {
		// The upsert above inserts the new identifier. Remove any older
		// catalog row for the same upstream asset so a rename leaves one row.
		if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE target_id=? AND source_id=? AND value<>? AND COALESCE(source,'')<>'watch:scope'`, targetID, assetID, identifier); err != nil {
			return err
		}
	}
	resolved := "rejected"
	if decision == "approve" {
		resolved = "approved"
	}
	_, err = tx.ExecContext(ctx, `UPDATE bounty_scope_events SET status=?,resolved_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, resolved, eventID, targetID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// A rejection must not reach the scope-event hook. The hook can re-enter
	// ResolveScopeEvent with "approve" for favorited auto-scan programs, which
	// would reverse the operator's decision and queue a scan.
	if decision == "approve" && s.onScopeEvent != nil {
		s.onScopeEvent(ctx, targetID, programID, eventID, eventType, identifier)
	}
	return nil
}
