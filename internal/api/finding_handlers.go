package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
)

// handleSetFindingTriage records the operator's False-Positive triage decision on
// a vulnerability finding — confirmed (True Positive), false_positive, accepted_risk,
// fixed, or new — with an optional justification note. Triaged findings are filtered
// out of the working list and the exported report (FP management, section 3).
func (h *Handler) handleSetFindingTriage(w http.ResponseWriter, r *http.Request) {
	id, fid := mux.Vars(r)["id"], mux.Vars(r)["fid"]
	var req struct {
		Triage string `json:"triage"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !scanner.ValidTriageState(req.Triage) {
		h.writeError(w, http.StatusBadRequest, "invalid triage state (new|confirmed|false_positive|accepted_risk|fixed)")
		return
	}
	res, err := h.db.Exec(
		`UPDATE vuln_findings SET triage=?, triage_note=? WHERE id=? AND target_id=?`,
		req.Triage, req.Note, fid, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update triage")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id, "target_id": id})
	h.writeSuccess(w, map[string]string{"triage": req.Triage})
}

func targetListPagination(r *http.Request, defaultLimit, maxLimit int) (page, limit, offset int) {
	q := r.URL.Query()
	page, _ = strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ = strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if page-1 > math.MaxInt/limit {
		// Avoid wrapping (page-1)*limit negative, which SQLite reads as OFFSET 0
		// and would silently return page 1 for an extreme page number.
		offset = math.MaxInt
	} else {
		offset = (page - 1) * limit
	}
	if rawOffset := strings.TrimSpace(q.Get("offset")); rawOffset != "" {
		if parsed, err := strconv.Atoi(rawOffset); err == nil && parsed >= 0 {
			offset = parsed
			// Keep the reported page in sync when a client paginates by raw
			// offset instead of page number.
			if q.Get("page") == "" {
				page = (offset / limit) + 1
			}
		}
	}
	return page, limit, offset
}

func escapeFindingLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(s)) + "%"
}

func (h *Handler) handleListSubdomains(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	q := r.URL.Query()
	page, limit, offset := targetListPagination(r, 200, 500)
	alive := q.Get("alive")
	search := strings.TrimSpace(q.Get("search"))
	if search == "" {
		search = strings.TrimSpace(q.Get("q"))
	}
	newOnly := q.Get("new_only") == "1" || strings.EqualFold(q.Get("new_only"), "true")

	where := " WHERE target_id = ? AND COALESCE(catchall,0) = 0"
	args := []any{id}

	if alive == "true" {
		where += " AND is_alive = 1"
	} else if alive == "false" {
		where += " AND is_alive = 0"
	}
	if newOnly {
		where += " AND created_at >= datetime('now', '-24 hours')"
	}
	if search != "" {
		like := escapeFindingLike(search)
		where += ` AND (subdomain LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\' OR page_title LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}

	dir := "ASC"
	if strings.EqualFold(strings.TrimSpace(q.Get("dir")), "desc") {
		dir = "DESC"
	}
	orderCol := "subdomain"
	switch strings.ToLower(strings.TrimSpace(q.Get("sort"))) {
	case "created":
		orderCol = "created_at"
	case "status":
		orderCol = "COALESCE(status_code, 0)"
	}
	orderBy := fmt.Sprintf(" ORDER BY %s %s, id %s", orderCol, dir, dir)

	var total int
	if err := h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM subdomains"+where, args...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to count subdomains")
		return
	}

	query := `SELECT id, target_id, subdomain, ip, is_alive, status_code, page_title,
		has_https, has_http, response_time_ms, technologies, server, framework, cdn, waf,
		COALESCE(source,'dns'), last_seen, created_at
		FROM subdomains` + where + orderBy + " LIMIT ? OFFSET ?"
	dataArgs := append(append([]any{}, args...), limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, dataArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query subdomains")
		return
	}
	defer rows.Close()

	subs := make([]models.Subdomain, 0)
	for rows.Next() {
		var s models.Subdomain
		var techsJSON string
		var isAlive, hasHTTPS, hasHTTP int
		err := rows.Scan(&s.ID, &s.TargetID, &s.Subdomain, &s.IP, &isAlive,
			&s.StatusCode, &s.PageTitle, &hasHTTPS, &hasHTTP,
			&s.ResponseTimeMs, &techsJSON, &s.Server, &s.Framework,
			&s.CDN, &s.WAF, &s.Source, &s.LastSeen, &s.CreatedAt)
		if err != nil {
			continue
		}
		s.IsAlive = isAlive == 1
		s.HasHTTPS = hasHTTPS == 1
		s.HasHTTP = hasHTTP == 1
		s.Technologies = models.JSONToStringSlice(techsJSON)
		subs = append(subs, s)
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  subs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListHTTPServices(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	q := r.URL.Query()
	page, limit, offset := targetListPagination(r, 200, 500)
	search := strings.TrimSpace(q.Get("search"))
	if search == "" {
		search = strings.TrimSpace(q.Get("q"))
	}
	statusFilter := strings.TrimSpace(q.Get("status"))
	statusClass := strings.TrimSpace(q.Get("status_class"))
	newOnly := q.Get("new_only") == "1" || strings.EqualFold(q.Get("new_only"), "true")

	// A seed becomes an observed service only after a valid code and a probe
	// tier are committed with it. Status-zero seeds stay out of this view.
	const observed = `((COALESCE(source,'probe')='probe' AND status_code BETWEEN 100 AND 599)
		OR (COALESCE(source,'')='seed' AND status_code BETWEEN 100 AND 599 AND COALESCE(probe_tier,'')<>''))`
	where := " WHERE target_id = ? AND " + observed
	args := []any{id}

	if search != "" {
		like := escapeFindingLike(search)
		where += ` AND (url LIKE ? ESCAPE '\' OR title LIKE ? ESCAPE '\')`
		args = append(args, like, like)
	}

	if statusFilter != "" {
		var statusCode int
		fmt.Sscanf(statusFilter, "%d", &statusCode)
		if statusCode > 0 {
			where += " AND status_code = ?"
			args = append(args, statusCode)
		}
	}
	switch statusClass {
	case "2":
		where += " AND status_code BETWEEN ? AND ?"
		args = append(args, 200, 299)
	case "3":
		where += " AND status_code BETWEEN ? AND ?"
		args = append(args, 300, 399)
	case "4":
		where += " AND status_code BETWEEN ? AND ?"
		args = append(args, 400, 499)
	case "5":
		where += " AND status_code BETWEEN ? AND ?"
		args = append(args, 500, 599)
	}
	if newOnly {
		where += " AND created_at >= datetime('now', '-24 hours')"
	}

	dir := "ASC"
	if strings.EqualFold(strings.TrimSpace(q.Get("dir")), "desc") {
		dir = "DESC"
	}
	orderCol := "url"
	switch strings.ToLower(strings.TrimSpace(q.Get("sort"))) {
	case "created":
		orderCol = "created_at"
	case "size":
		orderCol = "content_length"
	case "status":
		orderCol = "status_code"
	}
	orderBy := fmt.Sprintf(" ORDER BY %s %s, id %s", orderCol, dir, dir)

	var total int
	if err := h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM http_services"+where, args...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to count http services")
		return
	}

	query := `SELECT id, target_id, url, status_code, title, server, content_type,
		content_length, redirect_url, technologies, response_time_ms, last_seen, created_at,
		COALESCE(waf,''), COALESCE(cms,'')
		FROM http_services` + where + orderBy + " LIMIT ? OFFSET ?"
	dataArgs := append(append([]any{}, args...), limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, dataArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query http services")
		return
	}
	defer rows.Close()

	services := make([]models.HTTPService, 0)
	for rows.Next() {
		var s models.HTTPService
		var techsJSON string
		err := rows.Scan(&s.ID, &s.TargetID, &s.URL, &s.StatusCode, &s.Title,
			&s.Server, &s.ContentType, &s.ContentLength, &s.RedirectURL,
			&techsJSON, &s.ResponseTimeMs, &s.LastSeen, &s.CreatedAt, &s.WAF, &s.CMS)
		if err != nil {
			continue
		}
		s.Technologies = models.JSONToStringSlice(techsJSON)
		services = append(services, s)
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  services,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListJSFiles(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, size, hash, analyzed, last_seen, created_at
		FROM js_files WHERE target_id = ? ORDER BY url
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	files := make([]models.JSFile, 0)
	for rows.Next() {
		var f models.JSFile
		var analyzed int
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.Size, &f.Hash, &analyzed, &f.LastSeen, &f.CreatedAt)
		if err == nil {
			f.Analyzed = analyzed == 1
			files = append(files, f)
		}
	}
	h.writeSuccess(w, files)
}

func (h *Handler) handleListJSFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	severity := r.URL.Query().Get("severity")
	findingType := r.URL.Query().Get("type")

	query := `SELECT jf.id, jf.target_id, jf.js_file_id, COALESCE(jsf.url, ''), jf.type, jf.value, jf.context, jf.severity, COALESCE(jf.verified, 0), jf.created_at
		FROM js_findings jf
		LEFT JOIN js_files jsf ON jsf.id = jf.js_file_id
		WHERE jf.target_id = ?`
	args := []any{id}

	if severity != "" {
		query += " AND jf.severity = ?"
		args = append(args, severity)
	}
	if findingType != "" {
		query += " AND jf.type = ?"
		args = append(args, findingType)
	}
	query += " ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, jf.created_at DESC LIMIT 1000"

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.JSFinding, 0)
	for rows.Next() {
		var f models.JSFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.JSFileID, &f.JSFileURL, &f.Type, &f.Value, &f.Context, &f.Severity, &f.Verified, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListParameters(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	q := r.URL.Query()
	reflected := q.Get("reflected")
	search := strings.TrimSpace(q.Get("search"))
	if search == "" {
		search = strings.TrimSpace(q.Get("q"))
	}
	page, limit, offset := targetListPagination(r, 200, 500)

	where := " WHERE target_id = ?"
	args := []any{id}

	if reflected == "true" {
		where += " AND is_reflected = 1"
	}
	if search != "" {
		like := escapeFindingLike(search)
		where += ` AND (parameter LIKE ? ESCAPE '\' OR url LIKE ? ESCAPE '\')`
		args = append(args, like, like)
	}

	var total int
	if err := h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM parameters"+where, args...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to count parameters")
		return
	}

	query := `SELECT id, target_id, url, parameter, value, source, is_reflected, created_at
		FROM parameters` + where + " ORDER BY parameter ASC, id ASC LIMIT ? OFFSET ?"
	dataArgs := append(append([]any{}, args...), limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, dataArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	params := make([]models.Parameter, 0)
	for rows.Next() {
		var p models.Parameter
		var isReflected int
		err := rows.Scan(&p.ID, &p.TargetID, &p.URL, &p.Parameter, &p.Value, &p.Source, &isReflected, &p.CreatedAt)
		if err == nil {
			p.IsReflected = isReflected == 1
			params = append(params, p)
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  params,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListDirectoryFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, status_code, content_length, redirect_url, content_type, created_at
		FROM directory_findings WHERE target_id = ? ORDER BY content_length DESC, url
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.DirectoryFinding, 0)
	for rows.Next() {
		var f models.DirectoryFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.StatusCode, &f.ContentLength, &f.RedirectURL, &f.ContentType, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

// handleListAdminPanels returns one representative per stable panel fingerprint.
// The affected URL list retains every host/path behind that row so deduplication
// removes dashboard noise without hiding the actual attack surface.
func (h *Handler) handleListAdminPanels(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id,target_id,url,status_code,panel_type,product,title,redirect_url,
			content_hash,group_key,evidence,created_at,COALESCE(screenshot_id,'')
		FROM admin_panel_findings WHERE target_id=? AND status_code NOT BETWEEN 300 AND 399
		ORDER BY group_key,url`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	groups := make(map[string]*models.AdminPanelFinding)
	for rows.Next() {
		var f models.AdminPanelFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.StatusCode, &f.PanelType,
			&f.Product, &f.Title, &f.RedirectURL, &f.ContentHash, &f.GroupKey,
			&f.Evidence, &f.CreatedAt, &f.ScreenshotID); err != nil {
			continue
		}
		g := groups[f.GroupKey]
		if g == nil {
			f.AffectedURLs = []string{f.URL}
			f.AffectedCount = 1
			groups[f.GroupKey] = &f
			continue
		}
		g.AffectedURLs = append(g.AffectedURLs, f.URL)
		g.AffectedCount++
		// Prefer the shortest URL as the compact representative — but never
		// lose an already-captured screenshot just because a shorter URL
		// happened to be seen later without one of its own yet.
		if len(f.URL) < len(g.URL) {
			shot := g.ScreenshotID
			g.URL, g.ID, g.StatusCode, g.RedirectURL, g.CreatedAt = f.URL, f.ID, f.StatusCode, f.RedirectURL, f.CreatedAt
			g.ScreenshotID = f.ScreenshotID
			if g.ScreenshotID == "" {
				g.ScreenshotID = shot
			}
		} else if g.ScreenshotID == "" {
			g.ScreenshotID = f.ScreenshotID
		}
	}
	findings := make([]models.AdminPanelFinding, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.AffectedURLs)
		findings = append(findings, *g)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].AffectedCount != findings[j].AffectedCount {
			return findings[i].AffectedCount > findings[j].AffectedCount
		}
		return findings[i].URL < findings[j].URL
	})
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListBackupFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, status_code, content_length, COALESCE(file_type, ''), COALESCE(file_type, '') as backup_type, created_at
		FROM backup_findings WHERE target_id = ? ORDER BY content_length DESC, created_at DESC
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.BackupFinding, 0)
	for rows.Next() {
		var f models.BackupFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.StatusCode, &f.ContentLength, &f.FileType, &f.BackupType, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListOpenRedirects(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, redirect_to, parameter, verified, created_at
		FROM open_redirect_findings WHERE target_id = ? ORDER BY created_at DESC
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.OpenRedirectFinding, 0)
	for rows.Next() {
		var f models.OpenRedirectFinding
		var verified int
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.RedirectTo, &f.Parameter, &verified, &f.CreatedAt)
		if err == nil {
			f.Verified = verified == 1
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListNucleiFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	severity := r.URL.Query().Get("severity")
	search := r.URL.Query().Get("search")

	// Hide hits the verifier proved to be false positives (a reflected-but-encoded
	// XSS template, a same-origin "open redirect", etc.). Rejected rows are kept in
	// the DB for audit but never shown as actionable findings.
	//
	// COLLAPSE DUPLICATES: a single nuclei template routinely fires on hundreds of
	// near-identical URLs (e.g. the same template appended to every static asset),
	// which flooded this list with one logical issue repeated N times. We now group
	// by template_id and return ONE representative row per template — the shortest
	// (cleanest, least path-fuzzed) matched URL — plus affected_count = how many
	// URLs it matched. Severity/search filters apply before grouping.
	inner := `SELECT id, target_id, template_id, template_name, severity, matched_url, description, tags, meta,
		COALESCE(curl_command,'') AS curl_command, COALESCE(request,'') AS request,
		COALESCE(response,'') AS response, created_at,
		COUNT(*) OVER (PARTITION BY template_id) AS affected_count,
		ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
		FROM nuclei_findings WHERE target_id = ? AND COALESCE(verification,'unverified') != 'rejected'`
	args := []any{id}

	if severity != "" {
		inner += " AND severity = ?"
		args = append(args, severity)
	}
	if search != "" {
		inner += " AND (template_name LIKE ? OR matched_url LIKE ? OR description LIKE ?)"
		like := "%" + search + "%"
		args = append(args, like, like, like)
	}

	// Truncate the heavy free-text columns and bound the row count for the same
	// reason as vuln_findings: full request/response bodies across many rows can
	// OOM the browser tab (black screen). The full PoC still opens on demand.
	query := `SELECT id, target_id, template_id, template_name, severity, matched_url,
		SUBSTR(COALESCE(description,''),1,2000), tags, meta,
		SUBSTR(COALESCE(curl_command,''),1,4000),
		SUBSTR(COALESCE(request,''),1,4000),
		SUBSTR(COALESCE(response,''),1,4000),
		created_at, affected_count
		FROM (` + inner + `) WHERE rn = 1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         affected_count DESC, created_at DESC LIMIT 500`

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.NucleiFinding, 0)
	for rows.Next() {
		var f models.NucleiFinding
		var tagsJSON, metaJSON string
		err := rows.Scan(&f.ID, &f.TargetID, &f.TemplateID, &f.TemplateName,
			&f.Severity, &f.MatchedURL, &f.Description, &tagsJSON, &metaJSON,
			&f.CurlCommand, &f.Request, &f.Response, &f.CreatedAt, &f.AffectedCount)
		if err == nil {
			f.Tags = models.JSONToStringSlice(tagsJSON)
			f.Meta = models.JSONToMap(metaJSON)
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

// handleNucleiAffected returns EVERY matched URL for one template on a target —
// the full list behind a grouped finding's "affected_count", each with its own
// PoC (curl / request / response). This is what lets the UI/report expand a single
// collapsed row into "here are all N targets it fired on, with proof for each",
// instead of the other N-1 hits only ever appearing in the live log.
func (h *Handler) handleNucleiAffected(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	templateID := r.URL.Query().Get("template_id")
	if templateID == "" {
		h.writeError(w, http.StatusBadRequest, "template_id is required")
		return
	}
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT matched_url,
			SUBSTR(COALESCE(curl_command,''),1,4000),
			SUBSTR(COALESCE(request,''),1,6000),
			SUBSTR(COALESCE(response,''),1,6000),
			created_at
		FROM nuclei_findings
		WHERE target_id = ? AND template_id = ? AND COALESCE(verification,'unverified') != 'rejected'
		ORDER BY LENGTH(matched_url) ASC, created_at DESC LIMIT 1000
	`, id, templateID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type Affected struct {
		MatchedURL  string `json:"matched_url"`
		CurlCommand string `json:"curl_command"`
		Request     string `json:"request"`
		Response    string `json:"response"`
		CreatedAt   string `json:"created_at"`
	}
	out := make([]Affected, 0)
	for rows.Next() {
		var a Affected
		if err := rows.Scan(&a.MatchedURL, &a.CurlCommand, &a.Request, &a.Response, &a.CreatedAt); err == nil {
			out = append(out, a)
		}
	}
	h.writeSuccess(w, out)
}

// serveFileBody returns the capped content capture the MONITOR pass stored for
// a diffed asset (css_files / js_files): side=current (live capture) or
// side=old (previous capture rolled in at detection time). URL-keyed — the
// monitor records changes under the exact same URL string it tracks content
// for. Hard-scoped to the routed target: no cross-target reads. This is NOT a
// fetch proxy: it only ever returns content captured at detection time, so it
// has no request-driven SSRF surface.
func (h *Handler) serveFileBody(w http.ResponseWriter, r *http.Request, table, kind string) {
	id := mux.Vars(r)["id"]
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if rawURL == "" {
		h.writeError(w, http.StatusBadRequest, "url query parameter required")
		return
	}
	side := r.URL.Query().Get("side")
	if side != "old" && side != "current" {
		side = "current"
	}
	var storedURL, hash, content string
	var size int64
	var rowErr error
	if side == "old" {
		rowErr = h.db.QueryRowContext(r.Context(), `SELECT url, COALESCE(old_hash,''), COALESCE(old_body,'') FROM `+table+` WHERE target_id = ? AND url = ?`, id, rawURL).
			Scan(&storedURL, &hash, &content)
	} else {
		rowErr = h.db.QueryRowContext(r.Context(), `SELECT url, size, hash, COALESCE(body,'') FROM `+table+` WHERE target_id = ? AND url = ?`, id, rawURL).
			Scan(&storedURL, &size, &hash, &content)
	}
	if rowErr != nil {
		h.writeError(w, http.StatusNotFound, "no capture for this asset (the change predates content tracking, or the URL is not tracked)")
		return
	}
	h.writeSuccess(w, map[string]any{
		"kind":     kind,
		"url":      storedURL,
		"side":     side,
		"hash":     hash,
		"size":     size,
		"content":  content,
		"captured": strings.TrimSpace(content) != "",
	})
}

func (h *Handler) handleGetCSSFileBody(w http.ResponseWriter, r *http.Request) {
	h.serveFileBody(w, r, "css_files", "css")
}

func (h *Handler) handleGetJSFileBody(w http.ResponseWriter, r *http.Request) {
	h.serveFileBody(w, r, "js_files", "js")
}

func (h *Handler) handleListVulnFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	vulnType := r.URL.Query().Get("type")
	// status filter: 'finding' (default) | 'candidate' | 'all'. Candidates are
	// unconfirmed and kept out of the default view / severity counts.
	statusFilter := r.URL.Query().Get("status")
	if statusFilter == "" {
		statusFilter = "finding"
	}

	// Cap the heavy free-text columns HERE, in SQL. A single finding's evidence or
	// provenance can be a full multi-megabyte HTTP exchange; the list view only
	// shows a truncated preview anyway (the full evidence loads on demand via the
	// Evidence button / EvidenceViewer). Sending 500 rows × megabytes was building
	// a DOM large enough to OOM the browser tab — the "click Vulns/Candidates and
	// the page goes black" crash, worst during an active scan that keeps re-fetching.
	query := `SELECT id, target_id, type, severity, url, parameter,
			SUBSTR(COALESCE(payload,''),1,2000),
			SUBSTR(COALESCE(evidence,''),1,4000),
			COALESCE(confidence,0), COALESCE(priority,0), COALESCE(status,'finding'),
			SUBSTR(COALESCE(provenance,''),1,4000),
			COALESCE(lifecycle,'LEGACY'), COALESCE(candidate_id,''),
			COALESCE(triage,''), SUBSTR(COALESCE(triage_note,''),1,1000), created_at,
			COALESCE(screenshot_id,'')
		FROM vuln_findings WHERE target_id = ?`
	args := []any{id}

	if vulnType != "" {
		query += " AND type = ?"
		args = append(args, vulnType)
	}
	if statusFilter != "all" {
		query += " AND COALESCE(status,'finding') = ?"
		args = append(args, statusFilter)
	}
	// False-Positive management: a specific triage view (e.g. ?triage=false_positive)
	// is shown on request; otherwise the working list HIDES findings marked as a
	// false positive so triaged noise stays out of the way.
	if tf := r.URL.Query().Get("triage"); tf != "" {
		query += " AND COALESCE(triage,'') = ?"
		args = append(args, tf)
	} else {
		query += " AND COALESCE(triage,'') != 'false_positive'"
	}

	// Rank by priority (severity × confidence) first — the genuinely
	// exploitable, high-confidence issues surface at the top.
	query += " ORDER BY priority DESC, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC LIMIT 500"

	rows, err := h.db.Query(query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type VulnFinding struct {
		ID           string `json:"id"`
		TargetID     string `json:"target_id"`
		Type         string `json:"type"`
		Severity     string `json:"severity"`
		URL          string `json:"url"`
		Parameter    string `json:"parameter"`
		Payload      string `json:"payload"`
		Evidence     string `json:"evidence"`
		Confidence   int    `json:"confidence"`
		Priority     int    `json:"priority"`
		Status       string `json:"status"`
		Provenance   string `json:"provenance"`
		Lifecycle    string `json:"lifecycle"`
		CandidateID  string `json:"candidate_id"`
		Triage       string `json:"triage"`
		TriageNote   string `json:"triage_note"`
		CreatedAt    string `json:"created_at"`
		ScreenshotID string `json:"screenshot_id,omitempty"`
	}
	findings := make([]VulnFinding, 0)
	for rows.Next() {
		var f VulnFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.Type, &f.Severity, &f.URL, &f.Parameter, &f.Payload, &f.Evidence, &f.Confidence, &f.Priority, &f.Status, &f.Provenance, &f.Lifecycle, &f.CandidateID, &f.Triage, &f.TriageNote, &f.CreatedAt, &f.ScreenshotID); err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}
