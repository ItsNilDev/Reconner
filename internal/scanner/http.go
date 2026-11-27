package scanner

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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
	Location      string   `json:"location"`
	Technologies  []string `json:"tech"`
	ResponseTime  string   `json:"response_time"`
}

func (o *httpxOutput) subdomain() string {
	if o.Input != "" {
		return o.Input
	}
	return o.Host
}

func normalizeHostName(raw string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
}

func uniqueHostVariants(norm, raw string, extras []string) []string {
	seen := make(map[string]bool, len(extras)+2)
	out := make([]string, 0, len(extras)+2)
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(norm)
	add(raw)
	for _, e := range extras {
		add(e)
	}
	return out
}

func effectiveRedirectURL(out httpxOutput) string {
	if redir := strings.TrimSpace(out.RedirectURL); redir != "" {
		return redir
	}
	if loc := strings.TrimSpace(out.Location); loc != "" && isRedirectStatus(out.StatusCode) {
		return normalizeRedirectTarget(out.URL, loc)
	}
	return ""
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
	seenNorm := map[string]bool{}
	hostIPs := map[string][]net.IP{}
	rawSubdomainsByNorm := map[string][]string{}
	for rows.Next() {
		var sub, ip string
		if err := rows.Scan(&sub, &ip); err != nil {
			continue
		}
		norm := normalizeHostName(sub)
		if norm == "" {
			continue
		}
		if !seenNorm[norm] {
			seenNorm[norm] = true
			hosts = append(hosts, norm)
		}
		rawSubdomainsByNorm[norm] = append(rawSubdomainsByNorm[norm], sub)
		if parsed := net.ParseIP(ip); parsed != nil {
			hostIPs[norm] = append(hostIPs[norm], parsed)
		} else if ip != "" {
			// A stored address list is kept as delimited text.
			for _, part := range strings.FieldsFunc(ip, func(r rune) bool {
				return r == ',' || r == ' ' || r == ';' || r == '\n'
			}) {
				if parsed := net.ParseIP(strings.TrimSpace(part)); parsed != nil {
					hostIPs[norm] = append(hostIPs[norm], parsed)
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
	excl := exclusionsFromContext(ctx)
	if excl.Empty() {
		var exclErr error
		excl, exclErr = LoadExclusionsE(ctx, s.db, targetID)
		if exclErr != nil {
			return fmt.Errorf("load target exclusions: %w", exclErr)
		}
	}
	if !excl.Empty() {
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
		return s.basicHTTPProbeWithVariants(ctx, targetID, hosts, rawSubdomainsByNorm, logFn)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(strings.Join(hosts, "\n")); err != nil {
		tmpFile.Close()
		if watchModeEnabled(ctx) {
			return fmt.Errorf("write httpx host list: %w", err)
		}
		return s.basicHTTPProbeWithVariants(ctx, targetID, hosts, rawSubdomainsByNorm, logFn)
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

	obsType := ObservationDeep
	if watchMode {
		obsType = ObservationWatch
	}
	preloadedBaselines := s.preloadBaselines(ctx, targetID, obsType)

	var mu sync.Mutex
	probed := 0
	corruptLines := 0
	// Watch tier: the hosts that came back from the HTTP phase. Only these are
	// considered for scope landing — a host that was never probed is not
	// verified and must not become approved scope.
	var probedHosts []string
	seenHost := map[string]bool{}
	pendingConfirm := map[string]httpxOutput{}
	var pendingConfirmOrder []string

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

			serviceURL := NormalizeServiceURL(out.URL)
			redir := effectiveRedirectURL(out)
			rawHost := out.subdomain()
			normHost := normalizeHostName(rawHost)

			needsConfirm := false
			if serviceURL != "" && ValidHTTPStatus(out.StatusCode) {
				if b, ok := preloadedBaselines[serviceURL]; ok &&
					ValidHTTPStatus(b.status) && b.status != out.StatusCode &&
					!isEquivalentRedirectStatus(serviceURL, b.status, out.StatusCode, b.redirect, redir) {
					needsConfirm = true
				}
			}

			if needsConfirm {
				mu.Lock()
				if _, exists := pendingConfirm[serviceURL]; !exists {
					pendingConfirmOrder = append(pendingConfirmOrder, serviceURL)
				}
				pendingConfirm[serviceURL] = out
				probed++
				if watchMode && normHost != "" && !seenHost[normHost] {
					seenHost[normHost] = true
					probedHosts = append(probedHosts, normHost)
				}
				if probed%20 == 0 {
					logFn("info", "http_probe", fmt.Sprintf("Probed %d hosts...", probed))
				}
				mu.Unlock()
				return
			}

			effectiveStatus, err := s.storeHTTPServiceWithOptions(ctx, targetID, out, rawSubdomainsByNorm, false)
			if err != nil {
				s.logger.Error("Failed to store HTTP service", "error", err)
				return
			}

			// Only a committed, valid observation advances liveness. A
			// status-zero response is not proof that the host is alive.
			if ValidHTTPStatus(effectiveStatus) {
				if err := s.updateSubdomainAliveWithVariants(ctx, targetID, rawHost, rawSubdomainsByNorm[normHost], effectiveStatus, out.Technologies, out.WebServer); err != nil {
					s.logger.Error("Failed to update subdomain", "error", err)
				}
				mu.Lock()
				probed++
				if watchMode && normHost != "" && !seenHost[normHost] {
					seenHost[normHost] = true
					probedHosts = append(probedHosts, normHost)
				}
				if probed%20 == 0 {
					logFn("info", "http_probe", fmt.Sprintf("Probed %d hosts...", probed))
				}
				mu.Unlock()
			}
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

	// Post-httpx same-client confirmation stage: runs after RunWithCallback exits
	// (releasing Executor.semaphore) so stdout reading is never stalled and the
	// confirmation pass uses the exact same httpx flags, rate limit, and identity.
	if len(pendingConfirm) > 0 && ctx.Err() == nil {
		var confirmed map[string]httpxOutput
		if !watchMode || probeFailed == nil {
			confirmed = s.confirmHTTPXTransitions(ctx, targetID, pendingConfirmOrder, pendingConfirm, args, logFn)
		}
		for _, serviceURL := range pendingConfirmOrder {
			first := pendingConfirm[serviceURL]
			baselineStatus := preloadedBaselines[serviceURL].status
			conf, ok := confirmed[serviceURL]
			obsToStore, pinBaseline := resolveConfirmedTransition(baselineStatus, first, conf, ok)
			if pinBaseline {
				logFn("info", "http_probe", fmt.Sprintf("Unconfirmed status transition on %s (%d -> %d); pinning baseline status",
					serviceURL, baselineStatus, first.StatusCode))
			}
			rawHost := obsToStore.subdomain()
			normHost := normalizeHostName(rawHost)
			effectiveStatus, err := s.storeHTTPServiceWithOptions(ctx, targetID, obsToStore, rawSubdomainsByNorm, pinBaseline)
			if err != nil {
				s.logger.Error("Failed to store HTTP service", "error", err)
				continue
			}
			if ValidHTTPStatus(effectiveStatus) {
				if err := s.updateSubdomainAliveWithVariants(ctx, targetID, rawHost, rawSubdomainsByNorm[normHost], effectiveStatus, obsToStore.Technologies, obsToStore.WebServer); err != nil {
					s.logger.Error("Failed to update subdomain", "error", err)
				}
			}
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
		if err := s.basicHTTPProbeWithVariants(ctx, targetID, hosts, rawSubdomainsByNorm, logFn); err != nil {
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
		recordWatchMissesWithVariants(ctx, s.db, targetID, probedHosts, hosts, rawSubdomainsByNorm, logFn)
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
	excl := exclusionsFromContext(ctx)
	if excl.Empty() {
		var exclErr error
		excl, exclErr = LoadExclusionsE(ctx, s.db, targetID)
		if exclErr != nil {
			logFn("warn", "http_probe", fmt.Sprintf("Fingerprinting skipped: load exclusions: %v", exclErr))
			return
		}
	}
	if !excl.Empty() {
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

func (s *HTTPScanner) confirmHTTPXTransitions(ctx context.Context, targetID string, order []string, pending map[string]httpxOutput, baseArgs []string, logFn LogFunc) map[string]httpxOutput {
	confirmed := map[string]httpxOutput{}
	if len(order) == 0 || s.exec == nil || !s.exec.IsToolAvailable("httpx") {
		return confirmed
	}
	urls := make([]string, 0, len(order))
	for _, serviceURL := range order {
		if out, ok := pending[serviceURL]; ok && strings.TrimSpace(out.URL) != "" {
			urls = append(urls, strings.TrimSpace(out.URL))
		}
	}
	if len(urls) == 0 {
		return confirmed
	}
	confirmFile, err := os.CreateTemp("", "httpx-confirm-*.txt")
	if err != nil {
		logFn("warn", "http_probe", fmt.Sprintf("Failed to create httpx confirmation file: %v", err))
		return confirmed
	}
	defer os.Remove(confirmFile.Name())
	if _, err := confirmFile.WriteString(strings.Join(urls, "\n")); err != nil {
		confirmFile.Close()
		logFn("warn", "http_probe", fmt.Sprintf("Failed to write httpx confirmation file: %v", err))
		return confirmed
	}
	confirmFile.Close()

	confirmArgs := append([]string(nil), baseArgs...)
	replaced := false
	for i := 0; i+1 < len(confirmArgs); i++ {
		if confirmArgs[i] == "-l" {
			confirmArgs[i+1] = confirmFile.Name()
			replaced = true
			break
		}
	}
	if !replaced {
		confirmArgs = append([]string{"-l", confirmFile.Name()}, confirmArgs...)
	}

	logFn("info", "http_probe", fmt.Sprintf("Confirming %d drifted HTTP status transition(s) with httpx...", len(urls)))
	var mu sync.Mutex
	if err := s.exec.RunWithCallback(ctx, targetID, func(line string) {
		var out httpxOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			return
		}
		serviceURL := NormalizeServiceURL(out.URL)
		if serviceURL == "" || !ValidHTTPStatus(out.StatusCode) {
			return
		}
		mu.Lock()
		confirmed[serviceURL] = out
		mu.Unlock()
	}, "httpx", confirmArgs...); err != nil && ctx.Err() == nil {
		logFn("warn", "http_probe", fmt.Sprintf("httpx confirmation error: %v", err))
	}
	return confirmed
}

func resolveConfirmedTransition(baselineStatus int, first, conf httpxOutput, hasConf bool) (httpxOutput, bool) {
	if hasConf && conf.StatusCode == first.StatusCode {
		return first, false
	}
	if hasConf && ValidHTTPStatus(baselineStatus) && conf.StatusCode == baselineStatus {
		if conf.Input == "" {
			conf.Input = first.Input
		}
		if conf.Host == "" {
			conf.Host = first.Host
		}
		return conf, false
	}
	return first, true
}

func (s *HTTPScanner) lookupSubdomainID(ctx context.Context, targetID, rawHost string, rawByNorm map[string][]string) (string, error) {
	norm := normalizeHostName(rawHost)
	var extras []string
	if rawByNorm != nil {
		extras = rawByNorm[norm]
	}
	for _, candidate := range uniqueHostVariants(norm, rawHost, extras) {
		var subID string
		err := s.db.QueryRowContext(ctx, `SELECT id FROM subdomains WHERE target_id=? AND subdomain=?`,
			targetID, candidate).Scan(&subID)
		if err == nil && subID != "" {
			return subID, nil
		}
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}
	}
	return "", nil
}

func (s *HTTPScanner) storeHTTPService(ctx context.Context, targetID string, out httpxOutput) error {
	_, err := s.storeHTTPServiceWithOptions(ctx, targetID, out, nil, false)
	return err
}

func (s *HTTPScanner) storeHTTPServiceWithOptions(ctx context.Context, targetID string, out httpxOutput, rawByNorm map[string][]string, pinBaselineStatus bool) (int, error) {
	sortedTechs := append([]string(nil), out.Technologies...)
	sort.Strings(sortedTechs)

	subID, _ := s.lookupSubdomainID(ctx, targetID, out.subdomain(), rawByNorm)

	obsType := ObservationDeep
	tier := "deep"
	if watchModeEnabled(ctx) {
		obsType = ObservationWatch
		tier = "watch"
	}
	return s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID:          targetID,
		TaskID:            taskIDFromContext(ctx),
		URL:               out.URL,
		Host:              out.subdomain(),
		SubdomainID:       subID,
		StatusCode:        out.StatusCode,
		Title:             out.Title,
		Server:            out.WebServer,
		Technologies:      models.StringSliceToJSON(sortedTechs),
		RedirectURL:       effectiveRedirectURL(out),
		ContentType:       out.ContentType,
		ContentLength:     out.ContentLength,
		Source:            "probe",
		ProbeTier:         tier,
		Type:              obsType,
		PinBaselineStatus: pinBaselineStatus,
	})
}

func (s *HTTPScanner) updateSubdomainAlive(ctx context.Context, targetID, host string, statusCode int, techs []string, server string) error {
	return s.updateSubdomainAliveWithVariants(ctx, targetID, host, nil, statusCode, techs, server)
}

func (s *HTTPScanner) updateSubdomainAliveWithVariants(ctx context.Context, targetID, host string, rawVariants []string, statusCode int, techs []string, server string) error {
	if IsWildcardScopePattern(host) {
		return nil
	}
	norm := normalizeHostName(host)
	if norm == "" {
		norm = host
	}
	hasHTTPS := 0
	hasHTTP := 0

	// Match the exact host (scheme + host, optional port/path) instead of a
	// loose substring, so `api` no longer matches `myapi.example.com`.
	r := s.db.QueryRowContext(ctx, `
		SELECT
			SUM(CASE WHEN url LIKE 'https://%' THEN 1 ELSE 0 END),
			SUM(CASE WHEN url LIKE 'http://%' THEN 1 ELSE 0 END)
		FROM http_services
		WHERE target_id = ? AND (
			url = 'https://' || ? OR url LIKE 'https://' || ? || '/%' OR url LIKE 'https://' || ? || ':%' OR
			url = 'http://'  || ? OR url LIKE 'http://'  || ? || '/%' OR url LIKE 'http://'  || ? || ':%'
		)
	`, targetID, norm, norm, norm, norm, norm, norm)

	var httpsCount, httpCount *int
	if err := r.Scan(&httpsCount, &httpCount); err != nil && err != sql.ErrNoRows {
		return err
	}
	if httpsCount != nil && *httpsCount > 0 {
		hasHTTPS = 1
	}
	if httpCount != nil && *httpCount > 0 {
		hasHTTP = 1
	}

	sortedTechs := append([]string(nil), techs...)
	sort.Strings(sortedTechs)
	techsJSON := models.StringSliceToJSON(sortedTechs)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, variant := range uniqueHostVariants(norm, host, rawVariants) {
		if _, err = tx.ExecContext(ctx, `
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
		`, statusCode, techsJSON, server, hasHTTPS, hasHTTP, targetID, variant); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO watch_hosts(target_id,host,first_seen_at,first_alive_at,last_alive_at,alive_misses)
		VALUES(?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,0)
		ON CONFLICT(target_id,host) DO UPDATE SET
			first_alive_at=COALESCE(watch_hosts.first_alive_at,excluded.first_alive_at),
			last_alive_at=excluded.last_alive_at,
			alive_misses=0
	`, targetID, norm); err != nil {
		return err
	}
	return tx.Commit()
}

// recordWatchMisses advances the liveness state of hosts that were probed but
// produced no HTTP response. A single miss is state only; two consecutive
// misses flip is_alive off. This keeps a flaky response from toggling the feed.
func recordWatchMisses(ctx context.Context, db *database.DB, targetID string, probed []string, all []string, logFn LogFunc) {
	recordWatchMissesWithVariants(ctx, db, targetID, probed, all, nil, logFn)
}

func recordWatchMissesWithVariants(ctx context.Context, db *database.DB, targetID string, probed []string, all []string, rawByNorm map[string][]string, logFn LogFunc) {
	if len(all) == 0 {
		return
	}
	seen := make(map[string]bool, len(probed))
	for _, h := range probed {
		if norm := normalizeHostName(h); norm != "" {
			seen[norm] = true
		}
	}
	missed := 0
	for _, raw := range all {
		norm := normalizeHostName(raw)
		if norm == "" || seen[norm] {
			continue
		}
		var extras []string
		if rawByNorm != nil {
			extras = rawByNorm[norm]
		}
		hostMissed := false
		for _, variant := range uniqueHostVariants(norm, raw, extras) {
			res, err := db.ExecContext(ctx, `
				UPDATE subdomains SET alive_misses=alive_misses+1,
					is_alive=CASE WHEN alive_misses+1>=2 THEN 0 ELSE is_alive END
				WHERE target_id=? AND subdomain=?`, targetID, variant)
			if err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					hostMissed = true
				}
			}
		}
		if hostMissed {
			missed++
			_, _ = db.ExecContext(ctx, `UPDATE watch_hosts SET alive_misses=alive_misses+1 WHERE target_id=? AND host=?`, targetID, norm)
		}
	}
	if missed > 0 {
		logFn("info", "http_probe", fmt.Sprintf("%d probed host(s) gave no HTTP response; liveness state updated", missed))
	}
}

func (s *HTTPScanner) basicHTTPProbe(ctx context.Context, targetID string, hosts []string, logFn LogFunc) error {
	return s.basicHTTPProbeWithVariants(ctx, targetID, hosts, nil, logFn)
}

func (s *HTTPScanner) basicHTTPProbeWithVariants(ctx context.Context, targetID string, hosts []string, rawByNorm map[string][]string, logFn LogFunc) error {
	obsType := ObservationDeep
	if watchModeEnabled(ctx) {
		obsType = ObservationWatch
	}
	preloadedBaselines := s.preloadBaselines(ctx, targetID, obsType)

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

			norm := normalizeHostName(h)
			var variants []string
			if rawByNorm != nil {
				variants = rawByNorm[norm]
			}
			for _, scheme := range []string{"https", "http"} {
				rawURL := fmt.Sprintf("%s://%s", scheme, h)
				// Apply the same host gate to native fallback requests. A
				// redirect is checked again inside probeURLWithContext.
				if !urlHostInScope(ctx, rawURL) {
					continue
				}
				svc := probeURLWithContext(ctx, rawURL)
				if svc != nil {
					svc.ID = uuid.New().String()
					svc.TargetID = targetID
					pinBaseline := false
					if ValidHTTPStatus(svc.StatusCode) {
						serviceURL := NormalizeServiceURL(svc.URL)
						if b, ok := preloadedBaselines[serviceURL]; ok &&
							ValidHTTPStatus(b.status) && b.status != svc.StatusCode &&
							!isEquivalentRedirectStatus(serviceURL, b.status, svc.StatusCode, b.redirect, svc.RedirectURL) {
							confirm := probeURLWithContext(ctx, rawURL)
							if confirm != nil && confirm.StatusCode == b.status {
								confirm.ID = svc.ID
								confirm.TargetID = svc.TargetID
								svc = confirm
							} else if confirm == nil || confirm.StatusCode != svc.StatusCode {
								pinBaseline = true
							}
						}
					}
					effectiveStatus, err := s.storeBasicServiceWithOptions(ctx, svc, rawByNorm, pinBaseline)
					if err != nil {
						s.logger.Error("Store basic service failed", "error", err)
					} else if ValidHTTPStatus(effectiveStatus) {
						// Native fallback shares the committed success path with
						// the tool probe: inventory and host liveness advance together.
						if err := s.updateSubdomainAliveWithVariants(ctx, targetID, h, variants, effectiveStatus, nil, svc.Server); err != nil {
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
	_, err := s.storeBasicServiceWithOptions(ctx, svc, nil, false)
	return err
}

func (s *HTTPScanner) storeBasicServiceWithOptions(ctx context.Context, svc *models.HTTPService, rawByNorm map[string][]string, pinBaselineStatus bool) (int, error) {
	lookupHost := URLHost(svc.URL)
	if u, err := url.Parse(strings.TrimSpace(svc.URL)); err == nil && u.Hostname() != "" {
		lookupHost = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	}
	subID, err := s.lookupSubdomainID(ctx, svc.TargetID, lookupHost, rawByNorm)
	if err != nil {
		return 0, err
	}
	obsType := ObservationDeep
	tier := "deep"
	if watchModeEnabled(ctx) {
		obsType = ObservationWatch
		tier = "watch"
	}
	return s.recordObservationWithEffectiveStatus(ctx, HTTPObservation{
		TargetID:          svc.TargetID,
		TaskID:            taskIDFromContext(ctx),
		URL:               svc.URL,
		Host:              URLHost(svc.URL),
		SubdomainID:       subID,
		Technologies:      "[]",
		StatusCode:        svc.StatusCode,
		Title:             svc.Title,
		Server:            svc.Server,
		RedirectURL:       svc.RedirectURL,
		ContentType:       svc.ContentType,
		ContentLength:     svc.ContentLength,
		Source:            "probe",
		ProbeTier:         tier,
		Type:              obsType,
		PinBaselineStatus: pinBaselineStatus,
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
