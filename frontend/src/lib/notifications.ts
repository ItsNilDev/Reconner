import type { Notification } from './api'

export const sevDot: Record<string, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-accent',
}

const NOTIFICATIONS_CHANGED = 'recon:notifications-changed'

// Both bell surfaces listen for this event after a mark-read so the badge and
// the Alerts panel never show different unread counts.
export function notifyNotificationsChanged(source: 'topbar' | 'changelog' = 'changelog'): void {
  window.dispatchEvent(new CustomEvent(NOTIFICATIONS_CHANGED, { detail: { source } }))
}

export function onNotificationsChanged(handler: (source?: string) => void): () => void {
  const listener = (ev: Event) => {
    handler((ev as CustomEvent<{ source?: string }>).detail?.source)
  }
  window.addEventListener(NOTIFICATIONS_CHANGED, listener)
  return () => window.removeEventListener(NOTIFICATIONS_CHANGED, listener)
}

// Shared bell navigation. Both TopBar and the Changes notifications panel use
// the same mark-read call and route rules.

// Only these types carry a bell change_id that equals a feed row id. New hosts,
// findings and program notices use other identities, so an event deep link for
// them would open an empty Changes view.
const FEED_EVENT_TYPES = new Set([
  'status_change', 'http_change', 'page_change', 'tech_change',
  'redirect_change', 'content_change', 'js_change', 'css_change',
  'security_header_removed', 'header_regression', 'content_security_change',
])

// Monitor/watch bells open the Changes tab. These types do not carry a feed
// row id, so they get the tab without an &event= deep link.
const MONITOR_TYPES = new Set([
  'bounty_scope_change', 'scope_landed', 'watch_failed', 'watch_kind_conflict',
  'monitor_failed', 'monitor_escalation_started', 'scan_auto_paused',
])
// Verified finding bells open the Confirmed tab; the narrower checks get their
// own dedicated tab so the operator lands on the matching result list.
const FINDING_TYPES = new Set([
  'finding', 'vuln', 'new_vuln_finding', 'xss', 'sqli', 'ssrf', 'idor',
  'takeover', 'lfi', 'ssti', 'cmdi', 'xxe', 'csrf', 'cors', 'jwt', 'authz',
  'ato', 'oast', 'cache_poison', 'file_upload', 'nosqli', 'blh', 'csti',
])
const FINDING_TAB: Record<string, string> = {
  nuclei: 'nuclei', js_finding: 'js-findings', backup: 'backups',
  open_redirect: 'redirects', admin_panel: 'admin-panels',
}
export function openNotification(
  n: Notification,
  navigate: (path: string) => void,
  markRead: (ids: string[]) => Promise<unknown>,
  source: 'topbar' | 'changelog' = 'changelog',
): void {
  if (!n.is_read) void markRead([n.id]).then(() => notifyNotificationsChanged(source)).catch(() => {})
  if (n.target_id) {
    // A new-host bell carries the discovered names in metadata. Route to the
    // Changes tab filtered to the first host instead of the generic target
    // landing page (B4).
    const hosts = n.metadata?.hosts
    const first = Array.isArray(hosts) && typeof hosts[0] === 'string' ? hosts[0] : ''
    const eventID = n.metadata?.change_id || n.metadata?.event_id || n.change_id
    if (FEED_EVENT_TYPES.has(n.type) && typeof eventID === 'string' && eventID) {
      navigate(`/targets/${n.target_id}?tab=monitor&event=${encodeURIComponent(eventID)}`)
    } else if (MONITOR_TYPES.has(n.type)) {
      navigate(`/targets/${n.target_id}?tab=monitor`)
    } else if (FINDING_TYPES.has(n.type)) {
      navigate(`/targets/${n.target_id}?tab=vulns`)
    } else if (FINDING_TAB[n.type]) {
      navigate(`/targets/${n.target_id}?tab=${FINDING_TAB[n.type]}`)
    } else {
      navigate(first
        ? `/targets/${n.target_id}?tab=monitor&q=${encodeURIComponent(first)}`
        : `/targets/${n.target_id}`)
    }
  }
  else if (n.url.startsWith('/') && !n.url.startsWith('//')) navigate(n.url)
  else if (/^https?:\/\//i.test(n.url)) window.open(n.url, '_blank', 'noopener,noreferrer')
}
