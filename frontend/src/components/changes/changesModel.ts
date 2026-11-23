import { diffWordsWithSpace } from 'diff'
import type { ChangeCategory, ChangeEntry, MonitoringChange } from '../../types'

export type ChangeFilter = ChangeCategory | 'all'

export const CHANGE_FILTERS: { id: ChangeFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'security', label: 'Security' },
  { id: 'scripts', label: 'Scripts' },
  { id: 'http', label: 'HTTP' },
  { id: 'tech', label: 'Tech' },
  { id: 'headers', label: 'Headers' },
  { id: 'assets', label: 'Assets & scope' },
  { id: 'alerts', label: 'Alerts' },
]

// Exact mirror of changeCategoryExpr in internal/api/changes_handlers.go.
// Keep both lists in sync: the feed ships a `category` column computed there.
export const CATEGORY_BY_TYPE: Record<string, ChangeCategory> = {
  status_change: 'http',
  http_change: 'http',
  redirect_change: 'http',
  page_change: 'http',
  js_change: 'scripts',
  css_change: 'scripts',
  tech_change: 'tech',
  new_subdomain: 'assets',
  new_host: 'assets',
  scope_proposed: 'assets',
  scope_landed: 'assets',
  scope_modified: 'assets',
  scope_removed: 'assets',
  scope_rejected: 'assets',
  watch_failed: 'alerts',
  watch_kind_conflict: 'alerts',
  monitor_failed: 'alerts',
  monitor_escalation_started: 'alerts',
  scan_auto_paused: 'alerts',
  bounty_scope_change: 'alerts',
}

// The default feed and the bell deliberately show a small allow-list. Go
// mirrors these lists in the feed query, so the API and the UI agree on what
// counts as a real event. Findings, scan_deep and routine monitor diffs stay
// out of the default view.
export const NOTIFICATION_ALLOWED_TYPES = [
  'watch_failed', 'watch_kind_conflict', 'monitor_failed',
  'monitor_escalation_started', 'scan_auto_paused',
  'new_host',
] as const

export const BOUNTY_SCOPE_TYPES = [
  'scope_proposed', 'scope_landed', 'scope_modified', 'scope_removed', 'scope_rejected',
] as const

const notificationTypes: ReadonlySet<string> = new Set(NOTIFICATION_ALLOWED_TYPES)
const bountyScopeTypes: ReadonlySet<string> = new Set(BOUNTY_SCOPE_TYPES)

// isDefaultFeedRow keeps the default view free of routine monitor noise even
// when the server sends a wider feed. Category chips opt out of this filter so
// an operator can still inspect deep changes explicitly.
export function isDefaultFeedRow(row: { source?: string; change_type?: string }): boolean {
  const type = row.change_type || ''
  // An actual HTTP status transition is a daily signal. Routine monitor diffs
  // stay out of the default view (A8).
  if (row.source === 'monitor') return type === 'http_change' || type === 'status_change'
  if (row.source === 'watch') return type === 'new_subdomain'
  if (row.source === 'bounty') return bountyScopeTypes.has(type)
  if (row.source === 'notification') return notificationTypes.has(type)
  return false
}

export function categoryForChangeType(changeType: string): ChangeCategory {
  if (!changeType) return 'http'
  const exact = CATEGORY_BY_TYPE[changeType]
  if (exact) return exact
  if (changeType === 'js_change' || changeType.includes('script') || changeType.includes('stylesheet')) return 'scripts'
  if (changeType.includes('header')) return 'headers'
  if (changeType.startsWith('security')) return 'security'
  return 'http'
}

// changeHosts returns the new-host names stored on a new_subdomain ChangeEntry.
// Returns null for any other change type, missing metadata, or a non-string
// hosts value so callers can keep the prior count-only rendering.
export function changeHosts(item: Pick<ChangeEntry, 'change_type' | 'metadata'>): string[] | null {
  if (item.change_type !== 'new_subdomain' && item.change_type !== 'new_host') return null
  const hosts = item.metadata?.hosts
  if (!Array.isArray(hosts)) return null
  const out = hosts.filter((h): h is string => typeof h === 'string' && h.length > 0)
  return out.length > 0 ? out : null
}

// Bucket order follows the API taxonomy: stylesheet/script markers win before
// the generic "security:" prefix, and any header change lands in Headers.
export const monitorRowKind = (c: { change_type?: string }): ChangeFilter => {
  const ct = typeof c?.change_type === 'string' ? c.change_type : ''
  return categoryForChangeType(ct)
}

export type ChangeBadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const changeBadgeVariant = (c: { severity?: string; change_type?: string }): ChangeBadgeVariant => {
  const sev = (c.severity || '').toLowerCase()
  if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'info') {
    return sev as ChangeBadgeVariant
  }
  const ct = typeof c.change_type === 'string' ? c.change_type : ''
  return ct === 'js_change' ? 'medium'
    : ct.startsWith('security') || ct.includes('header') ? 'high'
      : ct === 'tech_change' ? 'low'
        : 'info'
}

export interface ChangeLike {
  change_type?: string
  old_value?: string
  new_value?: string
  url?: string
}

export interface MonitorChangeGroup<T extends ChangeLike = MonitoringChange> {
  key: string
  rep: T
  items: T[]
  urls: string[]
}

export const OCCURRENCE_PAGE_SIZE = 200

export type GroupIdentity<T> = string | ((row: T) => string)

export function groupMonitorChanges<T extends ChangeLike>(rows: T[], identity: GroupIdentity<T> = ''): MonitorChangeGroup<T>[] {
  const groups = new Map<string, MonitorChangeGroup<T>>()
  for (const c of rows) {
    const id = typeof identity === 'function' ? identity(c) : identity
    const prefix = id ? `${id}\u0000` : ''
    const key = `${prefix}${c.change_type || ''}\u0000${c.old_value || ''}\u0000${c.new_value || ''}`
    const g = groups.get(key)
    if (g) g.items.push(c)
    else groups.set(key, { key, rep: c, items: [c], urls: [] })
  }
  for (const g of groups.values()) {
    g.urls = [...new Set(g.items.map(i => i.url || ''))]
  }
  return [...groups.values()]
}

export function parseStatusTransition(oldValue: string, newValue: string): { oldCode?: number; newCode?: number } {
  // Mirror changesStatusCodeExpr in changes_handlers.go: require the exact
  // "status=NNN " token with a trailing space and an in-range code. Dropping
  // the older free-text fallback keeps pills aligned with status filters.
  const pick = (value: string) => {
    const match = /(?:^|[\s,])status=([1-5]\d{2})\s/.exec(value || '')
    if (!match) return undefined
    const code = Number(match[1])
    return Number.isFinite(code) ? code : undefined
  }
  return { oldCode: pick(oldValue), newCode: pick(newValue) }
}

export interface InlineDiffPiece {
  kind: 'same' | 'added' | 'removed'
  text: string
}

export function inlineDiffPieces(oldValue: string, newValue: string): InlineDiffPiece[] {
  return diffWordsWithSpace(oldValue || '', newValue || '').map(part => ({
    kind: part.added ? 'added' : part.removed ? 'removed' : 'same',
    text: part.value,
  }))
}
