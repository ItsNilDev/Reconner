package api

import (
	"net/http"
	"strconv"
	"strings"
)

// Global findings view. The per-target tabs are the detail view; a community
// operator running many targets also wants ONE place that answers "what has
// Reconner actually found, everywhere, right now". handleListAllFindings
// aggregates confirmed findings across every finding store and every target
// the caller owns (all targets for an admin), newest/most-severe first, with
// the target each belongs to — the backing data for the top-level Findings page.

type allFinding struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Confidence int    `json:"confidence"`
	Priority   int    `json:"priority"`
	Status     string `json:"status"`
	Source     string `json:"source"`
	SourceTab  string `json:"source_tab"`
	Evidence   string `json:"evidence"`
	CreatedAt  string `json:"created_at"`
}

const unifiedFindingsCTE = `WITH unified AS (
	SELECT f.id, f.target_id, f.type,
		COALESCE(LOWER(f.severity),'medium') AS severity,
		COALESCE(f.url,'') AS url,
		COALESCE(f.parameter,'') AS parameter,
		COALESCE(f.payload,'') AS payload,
		COALESCE(f.confidence,0) AS confidence,
		COALESCE(f.priority,0) AS priority,
		COALESCE(f.status,'finding') AS status,
		'native' AS source,
		CASE WHEN COALESCE(f.status,'finding') = 'candidate' THEN 'candidates' ELSE 'vulns' END AS source_tab,
		SUBSTR(COALESCE(f.evidence,''), 1, 2000) AS evidence,
		COALESCE(f.created_at,'') AS created_at
	FROM vuln_findings f
	WHERE COALESCE(f.triage,'') != 'false_positive'

	UNION ALL

	SELECT n.id, n.target_id,
		COALESCE(n.template_id,'') AS type,
		COALESCE(LOWER(n.severity),'info') AS severity,
		COALESCE(n.matched_url,'') AS url,
		'' AS parameter,
		SUBSTR(COALESCE(n.curl_command,''), 1, 2000) AS payload,
		COALESCE(NULLIF(n.confidence, 0), 95) AS confidence,
		0 AS priority,
		'finding' AS status,
		'nuclei' AS source,
		'nuclei' AS source_tab,
		SUBSTR(COALESCE(n.description,''), 1, 2000) AS evidence,
		COALESCE(n.created_at,'') AS created_at
	FROM nuclei_findings n
	WHERE COALESCE(n.verification,'') = 'verified'

	UNION ALL

	SELECT b.id, b.target_id,
		'backup_exposure' AS type,
		'high' AS severity,
		COALESCE(b.url,'') AS url,
		'' AS parameter,
		'' AS payload,
		95 AS confidence,
		0 AS priority,
		'finding' AS status,
		'backup' AS source,
		'backups' AS source_tab,
		SUBSTR(COALESCE(b.file_type,''), 1, 2000) AS evidence,
		COALESCE(b.created_at,'') AS created_at
	FROM backup_findings b

	UNION ALL

	SELECT o.id, o.target_id,
		'open_redirect' AS type,
		'medium' AS severity,
		COALESCE(o.url,'') AS url,
		COALESCE(o.parameter,'') AS parameter,
		COALESCE(o.redirect_to,'') AS payload,
		CASE WHEN COALESCE(o.verified,0) = 1 THEN 90 ELSE 50 END AS confidence,
		0 AS priority,
		CASE WHEN COALESCE(o.status,'') = 'candidate' THEN 'candidate' ELSE 'finding' END AS status,
		'open_redirect' AS source,
		'redirects' AS source_tab,
		SUBSTR(COALESCE(o.provenance,''), 1, 2000) AS evidence,
		COALESCE(o.created_at,'') AS created_at
	FROM open_redirect_findings o
	WHERE (COALESCE(o.verified,0) = 1 AND COALESCE(o.status,'finding') = 'finding')
	   OR COALESCE(o.status,'') = 'candidate'

	UNION ALL

	SELECT j.id, j.target_id,
		COALESCE(j.type,'') AS type,
		COALESCE(LOWER(j.severity),'info') AS severity,
		COALESCE((SELECT jf.url FROM js_files jf WHERE jf.id = j.js_file_id), '') AS url,
		'' AS parameter,
		SUBSTR(COALESCE(j.value,''), 1, 2000) AS payload,
		95 AS confidence,
		0 AS priority,
		'finding' AS status,
		'js_secret' AS source,
		'js-findings' AS source_tab,
		SUBSTR(COALESCE(j.context,''), 1, 2000) AS evidence,
		COALESCE(j.created_at,'') AS created_at
	FROM js_findings j
	WHERE COALESCE(j.verified,0) = 1
)`

func escapeFindingsLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(s)) + "%"
}

// handleListAllFindings (GET /findings) returns findings across all finding
// stores and all of the caller's targets.
// Query params: status (finding|candidate|all, default finding), severity,
// type, source (native|nuclei|backup|open_redirect|js_secret), target_id,
// q (search domain/url/type/parameter), page (default 1), limit (default 200, max 500).
func (h *Handler) handleListAllFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	if status == "" {
		status = "finding"
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	offset := (page - 1) * limit

	fromWhere := ` FROM unified u JOIN targets t ON t.id = u.target_id WHERE 1=1`
	args := []any{}

	// Per-user isolation: a non-admin sees only findings on their own targets.
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		fromWhere += " AND t.owner_id = ?"
		args = append(args, uid)
	}
	if status != "all" {
		fromWhere += " AND u.status = ?"
		args = append(args, status)
	}
	if sev := strings.TrimSpace(q.Get("severity")); sev != "" {
		fromWhere += " AND LOWER(u.severity) = ?"
		args = append(args, strings.ToLower(sev))
	}
	if typ := strings.TrimSpace(q.Get("type")); typ != "" {
		fromWhere += " AND u.type = ?"
		args = append(args, typ)
	}
	if src := strings.TrimSpace(q.Get("source")); src != "" {
		fromWhere += " AND u.source = ?"
		args = append(args, src)
	}
	if tid := strings.TrimSpace(q.Get("target_id")); tid != "" {
		fromWhere += " AND u.target_id = ?"
		args = append(args, tid)
	}
	if search := strings.TrimSpace(q.Get("q")); search != "" {
		like := escapeFindingsLike(search)
		fromWhere += ` AND (LOWER(COALESCE(t.domain,'')) LIKE ? ESCAPE '\' OR LOWER(u.url) LIKE ? ESCAPE '\' OR LOWER(u.type) LIKE ? ESCAPE '\' OR LOWER(u.parameter) LIKE ? ESCAPE '\')`
		args = append(args, like, like, like, like)
	}

	var total int
	countQuery := unifiedFindingsCTE + ` SELECT COUNT(*)` + fromWhere
	if err := h.db.QueryRowContext(r.Context(), countQuery, args...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	selectQuery := unifiedFindingsCTE + `
		SELECT u.id, u.target_id, COALESCE(t.domain,''), u.type, u.severity,
			u.url, u.parameter, u.payload, u.confidence, u.priority, u.status,
			u.source, u.source_tab, u.evidence, u.created_at` + fromWhere + `
		ORDER BY u.priority DESC,
			CASE LOWER(u.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			u.created_at DESC, u.id DESC
		LIMIT ? OFFSET ?`
	selectArgs := append(append([]any{}, args...), limit, offset)

	rows, err := h.db.QueryContext(r.Context(), selectQuery, selectArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := []allFinding{}
	for rows.Next() {
		var f allFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.Domain, &f.Type, &f.Severity,
			&f.URL, &f.Parameter, &f.Payload, &f.Confidence, &f.Priority, &f.Status,
			&f.Source, &f.SourceTab, &f.Evidence, &f.CreatedAt); err != nil {
			h.writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    out,
		"total":   total,
		"page":    page,
		"limit":   limit,
	})
}
