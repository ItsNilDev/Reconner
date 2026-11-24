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
export function notifyNotificationsChanged(): void {
  window.dispatchEvent(new Event(NOTIFICATIONS_CHANGED))
}

export function onNotificationsChanged(handler: () => void): () => void {
  window.addEventListener(NOTIFICATIONS_CHANGED, handler)
  return () => window.removeEventListener(NOTIFICATIONS_CHANGED, handler)
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
export function openNotification(
  n: Notification,
  navigate: (path: string) => void,
  markRead: (ids: string[]) => Promise<unknown>,
): void {
  if (!n.is_read) void markRead([n.id]).then(notifyNotificationsChanged).catch(() => {})
  if (n.target_id) {
    // A new-host bell carries the discovered names in metadata. Route to the
    // Changes tab filtered to the first host instead of the generic target
    // landing page (B4).
    const hosts = n.metadata?.hosts
    const first = Array.isArray(hosts) && typeof hosts[0] === 'string' ? hosts[0] : ''
    const eventID = n.metadata?.change_id || n.metadata?.event_id || n.change_id
    if (FEED_EVENT_TYPES.has(n.type) && typeof eventID === 'string' && eventID) {
      navigate(`/targets/${n.target_id}?tab=monitor&event=${encodeURIComponent(eventID)}`)
    } else {
      navigate(first
        ? `/targets/${n.target_id}?tab=monitor&q=${encodeURIComponent(first)}`
        : `/targets/${n.target_id}`)
    }
  }
  else if (n.url.startsWith('/') && !n.url.startsWith('//')) navigate(n.url)
  else if (/^https?:\/\//i.test(n.url)) window.open(n.url, '_blank', 'noopener,noreferrer')
}
