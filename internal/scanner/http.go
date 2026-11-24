package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type HTTPScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewHTTPScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *HTTPScanner {
	return &HTTPScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

// SetBroadcast wires the task event bus. The probe captures the status baseline
// before an upsert, so the event must reach the same alert bridge as monitor
// changes. The constructor stays stable for the many direct test callers.
func (s *HTTPScanner) SetBroadcast(fn BroadcastFunc) { s.broadcast = fn }

type httpxOutput struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"` // original subdomain input
	Host          string   `json:"host"`  // resolved IP (not the subdomain)
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	RedirectURL   string   `json:"final_url"`
	Technologies  []string `json:"tech"`
	ResponseTime  string   `json:"response_time"`
}

func (o *httpxOutput) subdomain() string {
	if o.Input != "" {
		return o.Input
	}
	return o.Host
}

func (s *HTTPScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "http_probe", "Loading subdomains for HTTP probing...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT subdomain, COALESCE(ip,'') FROM subdomains
		WHERE target_id = ?
		  AND (COALESCE(ip,'') != '' OR COALESCE(source,'dns') IN ('seed','vhost'))
		  AND COALESCE(catchall,0) = 0
		ORDER BY subdomain
	`, targetID)
	if err != nil {
		return fmt.Errorf("query subdomains: %w", err)
	}

	var hosts []string
	hostIPs := map[string][]net.IP{}
	for rows.Next() {
		var sub, ip string
		if err := rows.Scan(&sub, &ip); err != nil {
			continue
		}
		hosts = append(hosts, sub)
		if parsed := net.ParseIP(ip); parsed != nil {
			hostIPs[sub] = append(hostIPs[sub], parsed)
		} else if ip != "" {
			// A stored address list is kept as delimited text.
			for _, part := range strings.FieldsFunc(ip, func(r rune) bool {
				return r == ',' || r == ' ' || r == ';' || r == '\n'
			}) {
				if parsed := net.ParseIP(strings.TrimSpace(part)); parsed != nil {
					hostIPs[sub] = append(hostIPs[sub], parsed)
				}
			}
		}
	}
	rows.Close()
	// A wildcard scope value such as "*.example.com" is a pattern, not a host.
	// It must never reach a probe, a live-service row, or a new-host event.
	// Old rows from earlier rounds are dropped here as well.
	{
		kept := hosts[:0]
		var dropped int
		for _, h := range hosts {
			if IsWildcardScopePattern(h) {
				dropped++
				continue
			}
			kept = append(kept, h)
		}
		hosts = kept
		if dropped > 0 {
			logFn("info", "http_probe", fmt.Sprintf("Skipped %d wildcard scope pattern(s) — patterns are not hosts", dropped))
		}
	}
	// Per-asset host scope: only probe hosts belonging to this scoped task.
	if hostScopeSet(ctx) != nil {
		kept := hosts[:0]
		for _, h := range hosts {
			if hostInScope(ctx, h) {
				kept = append(kept, h)
			}
		}
		hosts = kept
		logFn("info", "http_probe", fmt.Sprintf("Host-scope filter: %d host(s) in scope", len(hosts)))
	}
	// Out-of-scope exclusions (bug-bounty): drop excluded hosts BEFORE probing, so
	// nothing excluded ever becomes an http_service — the whole web pipeline reads
	// from http_services, so this one filter keeps every downstream module
	// (js, params, dast, nuclei…) off the excluded assets. This is the single
	// enforcement choke point for exclude_scope on the web side.
	if excl := LoadExclusions(ctx, s.db, targetID); !excl.Empty() {
		kept := hosts[:0]
		var dropped int
		for _, h := range hosts {
			var resolved []net.IP
			if len(hostIPs[h]) > 0 {
				resolved = hostIPs[h]
			} else if excl.HasCIDRs() && net.ParseIP(h) == nil {
				// CIDR rules need actual destination addresses. Resolve only
				// when the stored row has no address and a CIDR rule exists.
				if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h); err == nil {
					resolved = ips
				} else {
					// Destination cannot be checked reliably — keep it blocked.
					dropped++
					continue
				}
			}
			if excl.ExcludesWithIPs(h, resolved) {
				dropped++
				continue
			}
			kept = append(kept, h)
		}
		hosts = kept
		if dropped > 0 {
			logFn("info", "http_probe", fmt.Sprintf("Excluded %d out-of-scope host(s) from probing (exclude_scope)", dropped))
		}
	}

	if len(hosts) == 0 {
		logFn("info", "http_probe", "No subdomains found to probe")
		// An empty input is not a clean negative result. Report it as a blocked
		// phase so the UI can distinguish it from a healthy round with no changes.
		return BlockedPhase("no eligible hosts in current scope")
	}

	logFn("info", "http_probe", fmt.Sprintf("Probing %d hosts with httpx...", len(hosts)))

	// Write hosts to a temp file — httpx stdin mode is unreliable across versions
	tmpFile, err := os.CreateTemp("", "httpx-hosts-*.txt")
	if err != nil {
		logFn("warn", "http_probe", "Failed to create temp file, falling back to basic probe")
		if watchModeEnabled(ctx) {
			// The native prober opens its own connections and would run outside the
			// watch rate limit, so a watch round stops here instead.
			return fmt.Errorf("create httpx host list: %w", err)
		}
		return s.basicHTTPProbe(ctx, targetID, hosts, logFn)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(strings.Join(hosts, "\n")); err != nil {
		tmpFile.Close()
		if watchModeEnabled(ctx) {
			return fmt.Errorf("write httpx host list: %w", err)
		}
		return s.basicHTTPProbe(ctx, targetID, hosts, logFn)
	}
	tmpFile.Close()

	// Watch tier settings: its own thread count and rate limit, so a watch round
	// never competes with a deep scan for the box or for the target.
	probeThreads := s.cfg.Workers.HTTPProbing
	probeRate := s.cfg.Limits.HTTPRateLimit
	watchMode := watchModeEnabled(ctx)
	if watchMode {
		probeThreads = s.cfg.Limits.WatchHTTPThreads
		probeRate = s.cfg.Limits.WatchHTTPRateLimit
		if probeThreads <= 0 {
			probeThreads = 10
		}
		if probeRate < 0 {
			probeRate = 0
		}
	}

	args := []string{
		"-l", tmpFile.Name(),
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
		"-status-code",
		"-content-length",
		"-timeout", "10",
		"-threads", fmt.Sprintf("%d", probeThreads),
		"-retries", "1",
	}
	// Redirect following: the deep tier follows them (never forward program
	// headers to another host). The watch tier does NOT follow them: it only
	// wants to know whether the host is alive, and a redirect is a live host.
	// Dropping the follow saves one request per host. The recorded status code
	// becomes the 3xx instead of the final page, which changes no counter:
	// updateSubdomainAlive marks a host alive for ANY probe result.
	if !watchMode {
		args = append(args, "-follow-host-redirects")
	}
	// Rate-limit to avoid WAF bans (which cause false negatives) and respect
	// program policy.
	if probeRate > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", probeRate))
	}
	args = append(args, ToolRequestIdentityArgs(ctx, "httpx")...)

	var mu sync.Mutex
	probed := 0
	corruptLines := 0
	// Watch tier: the hosts that came back from the HTTP phase. Only these are
	// considered for scope landing — a host that was never probed is not
	// verified and must not become approved scope.
	var probedHosts []string
	seenHost := map[string]bool{}

	// A watch round must not confuse a tool outage with a healthy empty result.
	// recordWatchMisses increments alive_misses, so two failed rounds would flip
	// every host to is_alive=0. Track probe failures and abort before liveness is
	// touched. Partial observations already stored by the callback are retained.
	var probeFailed error
	if s.exec.IsToolAvailable("httpx") {
		err = s.exec.RunWithCallback(ctx, targetID, func(line string) {
			var out httpxOutput
			if err := json.Unmarshal([]byte(line), &out); err != nil {
				mu.Lock()
				corruptLines++
				mu.Unlock()
				return
			}

			stored := false
			if err := s.storeHTTPService(ctx, targetID, out); err != nil {
				s.logger.Error("Failed to store HTTP service", "error", err)
			} else {
				stored = true
			}

			// Only a committed, valid observation advances liveness. A
			// status-zero response is not proof that the host is alive.
			if stored && ValidHTTPStatus(out.StatusCode) {
				if err := s.updateSubdomainAlive(targetID, out.subdomain(), out.StatusCode, out.Technologies, out.WebServer); err != nil {
					s.logger.Error("Failed to update subdomain", "error", err)
				}
			}

			mu.Lock()
			probed++
			if watchMode {
				host := out.subdomain()
				if host != "" && !seenHost[host] {
					seenHost[host] = true
					probedHosts = append(probedHosts, host)
				}
			}
			if probed%20 == 0 {
				logFn("info", "http_probe", fmt.Sprintf("Probed %d hosts...", probed))
			}
			mu.Unlock()
		}, "httpx", args...)

		if err != nil && ctx.Err() == nil {
			logFn("warn", "http_probe", fmt.Sprintf("httpx error: %v", err))
			if watchMode {
				probeFailed = fmt.Errorf("httpx invocation failed: %w", err)
			}
		}
	} else {
		logFn("info", "http_probe", "httpx not available, using basic HTTP probing...")
		if watchMode {
			probeFailed = fmt.Errorf("httpx tool is not available")
		}
	}

	// Resilience gate: httpx is the whole scan's front door — every downstream
	// module (JS, params, crawl, all injection scanners) consumes http_services.
	// If httpx was missing, errored (e.g. a flag the installed build rejects →
	// exit status 2), or simply stored NOTHING for a non-empty host list, fall
	// back to the native Go prober so a single tool hiccup can't silently collapse
	// the entire scan to zero results.
	//
	// The watch tier does NOT use that fallback: the native prober opens its own
	// connections without the watch rate limit, so it would break the operator's
	// rate budget. A watch round that got no HTTP result simply lands nothing
	// (decision D53) and says so.
	if ctx.Err() == nil && probed == 0 && len(hosts) > 0 && !watchMode {
		if s.exec.IsToolAvailable("httpx") {
			logFn("warn", "http_probe", "httpx returned no live services — falling back to the native HTTP prober so the scan can proceed.")
		}
		if err := s.basicHTTPProbe(ctx, targetID, hosts, logFn); err != nil {
			return err
		}
		var recovered int
		_ = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM http_services WHERE target_id = ? AND COALESCE(source,'probe')='probe'`,
			targetID).Scan(&recovered)
		logFn("info", "http_probe", fmt.Sprintf("Native prober recovered %d live HTTP service(s).", recovered))
	}
	if corruptLines > 0 {
		logFn("warn", "http_probe", fmt.Sprintf("Ignored %d malformed httpx output line(s)", corruptLines))
	}
	if watchMode && probed == 0 && len(hosts) > 0 {
		logFn("warn", "http_probe", "httpx produced no live services — nothing is landed from this round (the native prober is skipped in watch mode).")
	}
	// A tool outage is a phase failure, not a healthy round. Abort before
	// recordWatchMisses can damage liveness or scope landing can claim results.
	if watchMode && probeFailed != nil {
		return probeFailed
	}

	// Scope landing (watch tier only): the stage runs AFTER the HTTP phase, so
	// only hosts that came back from the probe are considered. A round with no
	// HTTP result lands nothing.
	if watchMode {
		recordWatchMisses(ctx, s.db, targetID, probedHosts, hosts, logFn)
		if probed == 0 {
			logFn("info", "watch_scope", "HTTP phase produced no result: nothing landed this round")
		} else {
			// Landing is a silent audit write now. The host becomes approved
			// scope, but no bell, feed row, Telegram message or socket event is
			// produced here; those belong to the new-host emitter after this
			// phase and to real program scope changes.
			LandWatchScopeHosts(ctx, s.db, targetID, probedHosts, logFn)
		}
	}

	// Fingerprint the WAF/edge AND the CMS on each live host: the WAF name shows in
	// the HTTP tab, and a WordPress/Joomla/Drupal verdict lets the injection modules
	// skip a stock-CMS host (see loadCMSSkipHosts) instead of wasting time / raising
	// false positives on it.
	//
	// The watch tier skips it: the fingerprinters open their own connections, so
	// they would run outside the watch rate limit.
	if watchMode {
		logFn("info", "http_probe", "WAF/CMS fingerprinting skipped — watch rounds stay inside their rate limit.")
	} else {
		s.fingerprintHosts(ctx, targetID, logFn)
	}

	// A host whose probe landed on a CDN/bot-challenge page instead of the
	// real site poisons every downstream module that reads http_services
	// (JS analysis, params, directory discovery, nuclei, injection
	// scanners…) with a challenge page's title/content instead of the
	// target's own. Retry those specific hosts through a headless browser
	// before anything else consumes this data.
	// Deep scans only: a watch round must not start Chromium or open browser
	// connections outside the watch rate limit.
	if !watchMode {
		s.rescueChallengedHosts(ctx, targetID, logFn)
	}

	// Opt-in HTTP catch-all pass (global config http_catchall_detection, default
	// OFF, overridable per target): groups the 2xx fingerprints gathered above and
	// marks wildcard catch-all fleets (redirect-to-apex / homepage clones) so they
	// stop polluting the Hosts tab, reports and web modules. Reads stored data
	// only — no requests.
	if !watchMode && s.catchallEnabledForTarget(ctx, targetID) {
		if err := s.runCatchallPass(ctx, targetID, logFn); err != nil && ctx.Err() == nil {
			logFn("warn", "http_probe", fmt.Sprintf("HTTP catch-all pass failed: %v", err))
		}
	}

	// Authenticated-session preflight: validate configured identities NOW, at the
	// front of the scan, so an expired login is surfaced before every downstream
	// injection/authz module wastes itself against the logged-out app.
	//
	// The watch tier skips it: a watch round must not log into anything.
	if !watchMode {
		PreflightSessions(ctx, s, targetID, logFn)
	}

	logFn("info", "http_probe", "HTTP probing complete")
	return nil
}

// fingerprintHosts runs the native WAF and CMS fingerprinters over every live
// HTTP service of a target (bounded concurrency) and stores the results.
func (s *HTTPScanner) fingerprintHosts(ctx context.Context, targetID string, logFn LogFunc) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code > 0 AND COALESCE(source,'probe')='probe'`, targetID)
	if err != nil {
		return
	}
	var urls []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && u != "" {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)
	// A host excluded after it was first probed keeps its historical service
	// row, but no later phase may open a connection to it.
	if excl := LoadExclusions(ctx, s.db, targetID); !excl.Empty() {
		urls = FilterExcludedURLs(urls, excl)
	}
	if len(urls) == 0 {
		return
	}

	logFn("info", "http_probe", fmt.Sprintf("Fingerprinting WAF/edge + CMS on %d host(s)...", len(urls)))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var wafN, cmsN atomic.Int64
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			if waf := detectWAF(ctx, u); waf != "" {
				_, _ = s.db.Exec(`UPDATE http_services SET waf=? WHERE target_id=? AND url=?`, waf, targetID, u)
				wafN.Add(1)
			}
			if cms := detectCMS(ctx, u); cms != "" {
				_, _ = s.db.Exec(`UPDATE http_services SET cms=? WHERE target_id=? AND url=?`, cms, targetID, u)
				cmsN.Add(1)
			}
		}(u)
	}
	wg.Wait()
	if n := wafN.Load(); n > 0 {
		logFn("info", "http_probe", fmt.Sprintf("WAF/edge fingerprinted on %d host(s).", n))
	}
	if n := cmsN.Load(); n > 0 {
		logFn("info", "http_probe", fmt.Sprintf("CMS fingerprinted on %d host(s) — stock WP/Joomla/Drupal hosts will skip active injection scans.", n))
	}
}

func (s *HTTPScanner) storeHTTPService(ctx context.Context, targetID string, out httpxOutput) error {
	sortedTechs := append([]string(nil), out.Technologies...)
	sort.Strings(sortedTechs)

	var subID string
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM subdomains WHERE target_id=? AND subdomain=?`,
		targetID, out.subdomain()).Scan(&subID)

	obsType := ObservationDeep
	tier := "deep"
	if watchModeEnabled(ctx) {
		obsType = ObservationWatch
		tier = "watch"
	}
	return s.recordObservation(ctx, HTTPObservation{
		TargetID:      targetID,
		TaskID:        taskIDFromContext(ctx),
		URL:           out.URL,
		Host:          out.subdomain(),
		SubdomainID:   subID,
		StatusCode:    out.StatusCode,
		Title:         out.Title,
		Server:        out.WebServer,
		Technologies:  models.StringSliceToJSON(sortedTechs),
		RedirectURL:   out.RedirectURL,
		ContentType:   out.ContentType,
		ContentLength: out.ContentLength,
		Source:        "probe",
		ProbeTier:     tier,
		Type:          obsType,
	})
}

func (s *HTTPScanner) updateSubdomainAlive(targetID, host string, statusCode int, techs []string, server string) error {
	if IsWildcardScopePattern(host) {
		return nil
	}
	hasHTTPS := 0
	hasHTTP := 0

	var rows *dbRow
	// Match the exact host (scheme + host, optional port/path) instead of a
	// loose substring, so `api` no longer matches `myapi.example.com`.
	r := s.db.QueryRow(`
		SELECT
			SUM(CASE WHEN url LIKE 'https://%' THEN 1 ELSE 0 END),
			SUM(CASE WHEN url LIKE 'http://%' THEN 1 ELSE 0 END)
		FROM http_services
		WHERE target_id = ? AND (
			url = 'https://' || ? OR url LIKE 'https://' || ? || '/%' OR url LIKE 'https://' || ? || ':%' OR
			url = 'http://'  || ? OR url LIKE 'http://'  || ? || '/%' OR url LIKE 'http://'  || ? || ':%'
		)
	`, targetID, host, host, host, host, host, host)

	var httpsCount, httpCount *int
	r.Scan(&httpsCount, &httpCount)
	if httpsCount != nil && *httpsCount > 0 {
		hasHTTPS = 1
	}
	if httpCount != nil && *httpCount > 0 {
		hasHTTP = 1
	}

	sortedTechs := append([]string(nil), techs...)
	sort.Strings(sortedTechs)
	techsJSON := models.StringSliceToJSON(sortedTechs)
	_, err := s.db.Exec(`
		UPDATE subdomains SET
			is_alive = 1,
			status_code = ?,
			technologies = ?,
			server = ?,
			has_https = ?,
			has_http = ?,
			first_alive_at = COALESCE(first_alive_at, CURRENT_TIMESTAMP),
			last_alive_at = CURRENT_TIMESTAMP,
			alive_misses = 0
		WHERE target_id = ? AND subdomain = ?
	`, statusCode, techsJSON, server, hasHTTPS, hasHTTP, targetID, host)
	if err != nil {
		_ = rows
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO watch_hosts(target_id,host,first_seen_at,first_alive_at,last_alive_at,alive_misses)
		VALUES(?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,0)
		ON CONFLICT(target_id,host) DO UPDATE SET
			first_alive_at=COALESCE(watch_hosts.first_alive_at,excluded.first_alive_at),
			last_alive_at=excluded.last_alive_at,
			alive_misses=0
	`, targetID, host)

	_ = rows
	return err
}

// recordWatchMisses advances the liveness state of hosts that were probed but
// produced no HTTP response. A single miss is state only; two consecutive
// misses flip is_alive off. This keeps a flaky response from toggling the feed.
func recordWatchMisses(ctx context.Context, db *database.DB, targetID string, probed []string, all []string, logFn LogFunc) {
	if len(all) == 0 {
		return
	}
	seen := make(map[string]bool, len(probed))
	for _, h := range probed {
		seen[strings.ToLower(strings.TrimSpace(h))] = true
	}
	missed := 0
	for _, raw := range all {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" || seen[host] {
			continue
		}
		res, err := db.ExecContext(ctx, `
			UPDATE subdomains SET alive_misses=alive_misses+1,
				is_alive=CASE WHEN alive_misses+1>=2 THEN 0 ELSE is_alive END
			WHERE target_id=? AND subdomain=?`, targetID, host)
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				missed++
			}
			_, _ = db.ExecContext(ctx, `UPDATE watch_hosts SET alive_misses=alive_misses+1 WHERE target_id=? AND host=?`, targetID, host)
		}
	}
	if missed > 0 {
		logFn("info", "http_probe", fmt.Sprintf("%d probed host(s) gave no HTTP response; liveness state updated", missed))
	}
}

type dbRow = interface{}

func (s *HTTPScanner) basicHTTPProbe(ctx context.Context, targetID string, hosts []string, logFn LogFunc) error {
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, h)
				// Apply the same host gate to native fallback requests. A
				// redirect is checked again inside probeURLWithContext.
				if !urlHostInScope(ctx, url) {
					continue
				}
				svc := probeURLWithContext(ctx, url)
				if svc != nil {
					svc.ID = uuid.New().String()
					svc.TargetID = targetID
					if err := s.storeBasicService(ctx, svc); err != nil {
						s.logger.Error("Store basic service failed", "error", err)
					} else if ValidHTTPStatus(svc.StatusCode) {
						// Native fallback shares the committed success path with
						// the tool probe: inventory and host liveness advance together.
						if err := s.updateSubdomainAlive(targetID, h, svc.StatusCode, nil, svc.Server); err != nil {
							s.logger.Error("Update native probe liveness failed", "error", err)
						}
					}
				}
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func (s *HTTPScanner) storeBasicService(ctx context.Context, svc *models.HTTPService) error {
	obsType := ObservationDeep
	tier := "deep"
	if watchModeEnabled(ctx) {
		obsType = ObservationWatch
		tier = "watch"
	}
	return s.recordObservation(ctx, HTTPObservation{
		TargetID:      svc.TargetID,
		TaskID:        taskIDFromContext(ctx),
		URL:           svc.URL,
		Host:          URLHost(svc.URL),
		StatusCode:    svc.StatusCode,
		Title:         svc.Title,
		Server:        svc.Server,
		ContentType:   svc.ContentType,
		ContentLength: svc.ContentLength,
		Source:        "probe",
		ProbeTier:     tier,
		Type:          obsType,
	})
}

func (s *HTTPScanner) RunWithCallback(ctx context.Context, taskID string, callback func(line string), args ...string) error {
	return s.exec.RunWithCallback(ctx, taskID, callback, "httpx", args...)
}

func (s *HTTPScanner) ProbeURL(ctx context.Context, targetID, url string) error {
	if !s.exec.IsToolAvailable("httpx") {
		return nil
	}
	args := []string{
		"-u", url,
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
	}
	args = append(args, ToolRequestIdentityArgs(ctx, "httpx")...)
	_, err := s.exec.Run(ctx, "httpx", args...)
	return err
}

// RunWithInput probes an explicit newline-separated list of hosts via httpx.
// It correctly feeds the list through stdin (previously it used a plain
// RunWithCallback with `-l /dev/stdin`, which — like the old nuclei bug — read
// EOF and scanned nothing).
func (s *HTTPScanner) RunWithInput(ctx context.Context, taskID string, input string, logFn LogFunc) error {
	if !s.exec.IsToolAvailable("httpx") {
		return nil
	}

	args := []string{
		"-l", "/dev/stdin",
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
		"-status-code",
		"-content-length",
		"-follow-host-redirects", // never forward program headers to another host
		"-timeout", "10",
	}
	args = append(args, ToolRequestIdentityArgs(ctx, "httpx")...)
	return s.exec.RunWithInputCallback(ctx, strings.NewReader(input), taskID, func(line string) {
		var out httpxOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			return
		}
		if err := s.storeHTTPService(ctx, taskID, out); err != nil {
			s.logger.Error("Failed to store HTTP service from input run", "error", err)
		}
	}, "httpx", args...)
}
