package scanner

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Out-of-scope exclusions (bug-bounty). A target's exclude_scope is a
// comma/newline list of things that must NEVER be scanned even though they sit
// under the target: exact hosts, wildcard suffixes (*.dev.example.com or
// .dev.example.com), IPs, CIDRs, full URLs, and host:port pairs.
//
// Host-wide rules (a bare host, a full URL, or a CIDR) block every port on the
// host. A literal URL keeps that host-wide meaning: a rule such as
// https://admin.example.com/panel excludes the whole host, including other
// paths and ports. A bare host:port rule blocks only that destination; when a
// request destination does not carry a port, the rule is applied conservatively
// so an effective port cannot silently bypass it.
//
// Rules are enforced at the HTTP request boundary and in every stored-service
// consumer, so an excluded asset is never probed, fingerprinted, monitored, or
// reported. Historical rows remain available for review.

// ExclusionSet is a compiled, fast-to-query set of exclusions for one target.
type ExclusionSet struct {
	hosts     map[string]bool            // exact hostnames / IPs, host-wide
	endpoints map[string]map[string]bool // host -> blocked ports
	suffixes  []string                   // wildcard suffixes, stored as ".example.com"
	cidrs     []*net.IPNet
}

// Empty reports whether nothing is excluded (lets callers skip the check cheaply).
func (e ExclusionSet) Empty() bool {
	return len(e.hosts) == 0 && len(e.endpoints) == 0 && len(e.suffixes) == 0 && len(e.cidrs) == 0
}

// HasCIDRs reports whether the set contains network-range rules. It lets
// callers resolve destination addresses only when a CIDR rule can use them.
func (e ExclusionSet) HasCIDRs() bool { return len(e.cidrs) > 0 }

// normalizeExclusionHost lowercases a host, removes a trailing dot, and keeps
// bracketed IPv6 intact. It never strips a leading dot: callers use that to
// recognize a leading-dot suffix rule.
func normalizeExclusionHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// ParseManualExclusionPatterns splits a manual exclusion string on commas,
// whitespace, newlines, or semicolons, trimming tokens and deduplicating while
// preserving order.
func ParseManualExclusionPatterns(raw string) []string {
	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	})
	if len(tokens) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tokens))
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if _, ok := seen[tok]; ok {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

// CompileExclusions compiles a slice of exclusion patterns into an ExclusionSet.
func CompileExclusions(patterns []string) ExclusionSet {
	e := ExclusionSet{
		hosts:     map[string]bool{},
		endpoints: map[string]map[string]bool{},
	}
	for _, rawPattern := range patterns {
		for _, tok := range ParseManualExclusionPatterns(rawPattern) {
			if tok == "" {
				continue
			}

			// A full URL keeps its host-wide meaning. The path and any explicit
			// port are deliberately ignored so the rule cannot be narrowed by a
			// different path on the same host.
			if strings.Contains(tok, "://") {
				if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
					tok = u.Hostname()
				}
			}

			// CIDR. Normalize before parsing so IPv6 and casing behave. A token
			// with a slash that is not a CIDR is a schemeless path rule; let it
			// fall through to the host-wide truncation below.
			if strings.Contains(tok, "/") {
				if _, n, err := net.ParseCIDR(strings.ToLower(strings.TrimSpace(tok))); err == nil {
					e.cidrs = append(e.cidrs, n)
					continue
				}
			}

			// A schemeless rule such as admin.example.com/panel or
			// *.staging.example.com/* excludes the whole host. Paths never narrow
			// an exclusion, so drop everything after the first slash.
			if !strings.Contains(tok, "://") && strings.Contains(tok, "/") {
				tok = strings.SplitN(tok, "/", 2)[0]
				if tok == "" {
					continue
				}
			}

			// Leading-dot and "*.x" forms both mean the apex and all descendants.
			if strings.HasPrefix(tok, "*.") || strings.HasPrefix(tok, ".") {
				suf := strings.TrimPrefix(strings.TrimPrefix(tok, "*."), ".")
				suf = normalizeExclusionHost(suf)
				if suf != "" {
					e.hosts[suf] = true
					e.suffixes = append(e.suffixes, "."+suf)
				}
				continue
			}

			// Bare host:port (keeps bracketed IPv6 working).
			if host, port, err := net.SplitHostPort(tok); err == nil && port != "" {
				host = normalizeExclusionHost(host)
				if host != "" {
					if e.endpoints[host] == nil {
						e.endpoints[host] = map[string]bool{}
					}
					e.endpoints[host][port] = true
				}
				continue
			}

			if h := normalizeExclusionHost(tok); h != "" {
				e.hosts[h] = true
			}
		}
	}
	return e
}

// ParseExclusions compiles a raw manual exclusion string into an ExclusionSet.
func ParseExclusions(raw string) ExclusionSet {
	return CompileExclusions(ParseManualExclusionPatterns(raw))
}

// splitExclusionHostPort normalizes a request host and returns the host and an
// optional port. An empty port means the destination port is not known.
func splitExclusionHostPort(host string) (string, string) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	// Tolerate callers that pass a URL path as part of the destination.
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		return normalizeExclusionHost(h), p
	}
	return normalizeExclusionHost(host), ""
}

// excludesKnown reports whether a normalized host/port pair is excluded using
// only local information (no DNS resolution).
func (e ExclusionSet) excludesKnown(host, port string) bool {
	if host == "" {
		return false
	}
	if e.hosts[host] {
		return true
	}
	if ports := e.endpoints[host]; len(ports) > 0 {
		// The rule is port-specific. If the effective port is unknown, block
		// conservatively so a redirect or inferred port cannot slip through.
		if port == "" || ports[port] {
			return true
		}
	}
	for _, suf := range e.suffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	if len(e.cidrs) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range e.cidrs {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// Excludes reports whether host (a hostname or IP) is out of scope. It uses
// only the information in the host string. Use ExcludesDestination when CIDR
// rules must also be evaluated against the addresses a hostname resolves to.
func (e ExclusionSet) Excludes(host string) bool {
	if e.Empty() {
		return false
	}
	h, p := splitExclusionHostPort(strings.TrimSuffix(host, "."))
	return e.excludesKnown(h, p)
}

// ExcludesDestination reports whether a request destination is out of scope.
// CIDR rules are evaluated against the actual destination addresses, including
// addresses resolved from a hostname. If the destination cannot be resolved,
// the request stays blocked when any CIDR rule is present.
func (e ExclusionSet) ExcludesDestination(ctx context.Context, host string) bool {
	if e.Empty() {
		return false
	}
	h, p := splitExclusionHostPort(host)
	if e.excludesKnown(h, p) {
		return true
	}
	if len(e.cidrs) == 0 {
		return false
	}
	ips := []net.IP{}
	if ip := net.ParseIP(h); ip != nil {
		ips = append(ips, ip)
	} else if resolved, err := net.DefaultResolver.LookupIP(ctx, "ip", h); err == nil {
		ips = resolved
	} else {
		// The destination cannot be checked reliably; keep it blocked.
		return true
	}
	if len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		for _, n := range e.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ExcludesWithIPs reports whether host is excluded, evaluating CIDR rules
// against a supplied set of already-resolved addresses. It performs no DNS
// lookup, so callers that store addresses (for example subdomain rows) can
// enforce CIDR exclusions without another network call.
func (e ExclusionSet) ExcludesWithIPs(host string, ips []net.IP) bool {
	if e.Empty() {
		return false
	}
	h, p := splitExclusionHostPort(host)
	if e.excludesKnown(h, p) {
		return true
	}
	if len(e.cidrs) == 0 {
		return false
	}
	for _, ip := range ips {
		for _, n := range e.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// URLHost returns the host (with port, when present) of a URL or host string.
// It is used to apply one exclusion policy to stored service URLs and raw
// hostnames alike.
func URLHost(raw string) string {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			h := u.Hostname()
			if p := u.Port(); p != "" {
				return net.JoinHostPort(h, p)
			}
			// Infer the default port from the scheme. A rule for host:8443
			// must not block https://host/ (port 443). Without an inferred
			// port, excludesKnown blocks conservatively and loses the site.
			switch strings.ToLower(u.Scheme) {
			case "http":
				return net.JoinHostPort(h, "80")
			case "https":
				return net.JoinHostPort(h, "443")
			}
			return h
		}
	}
	return raw
}

// FilterExcludedURLs drops every URL whose host is excluded. It preserves the
// original strings so callers can keep using them as service keys.
func FilterExcludedURLs(urls []string, e ExclusionSet) []string {
	if e.Empty() {
		return urls
	}
	kept := urls[:0]
	for _, raw := range urls {
		if e.Excludes(URLHost(raw)) {
			continue
		}
		kept = append(kept, raw)
	}
	return kept
}

// FilterExcludedIPs drops every IP that falls under the target's exclusions
// (exact IP or an excluded CIDR), returning the kept list and how many were
// removed — so a network scan never probes an out-of-scope IP inside an
// otherwise in-scope range.
func FilterExcludedIPs(ips []string, e ExclusionSet) (kept []string, dropped int) {
	if e.Empty() {
		return ips, 0
	}
	kept = ips[:0]
	for _, ip := range ips {
		if e.Excludes(ip) {
			dropped++
			continue
		}
		kept = append(kept, ip)
	}
	return kept, dropped
}

// LoadExclusionsE reads and compiles a target's exclusions from target_exclusions.
// It returns the read error so a task can block before it sends any request. A
// read failure must never become an empty (permissive) exclusion set.
func LoadExclusionsE(ctx context.Context, db *database.DB, targetID string) (ExclusionSet, error) {
	if db == nil {
		return ExclusionSet{}, errors.New("database is nil")
	}
	rows, err := db.QueryContext(ctx, `SELECT pattern FROM target_exclusions WHERE target_id = ?`, targetID)
	if err != nil {
		return ExclusionSet{}, err
	}
	defer rows.Close()
	var patterns []string
	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err != nil {
			return ExclusionSet{}, err
		}
		patterns = append(patterns, pattern)
	}
	if err := rows.Err(); err != nil {
		return ExclusionSet{}, err
	}
	return CompileExclusions(patterns), nil
}

// ReplaceManualExclusionsTx replaces all manual exclusion rows for targetID
// while leaving bounty-managed rows intact.
func ReplaceManualExclusionsTx(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, targetID string, raw string) error {
	if exec == nil {
		return errors.New("database executor is nil")
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM target_exclusions WHERE target_id = ? AND source = 'manual'`, targetID); err != nil {
		return err
	}
	for _, pattern := range ParseManualExclusionPatterns(raw) {
		if _, err := exec.ExecContext(ctx,
			`INSERT INTO target_exclusions (id, target_id, source, program_id, pattern) VALUES (?, ?, 'manual', '', ?) ON CONFLICT(target_id, source, program_id, pattern) DO NOTHING`,
			uuid.NewString(), targetID, pattern,
		); err != nil {
			return err
		}
	}
	return nil
}
