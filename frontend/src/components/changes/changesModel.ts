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
  scope_rule_added: 'assets',
  scope_rule_removed: 'assets',
  scope_re_eligible: 'assets',
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
  'scope_rule_added', 'scope_rule_removed', 'scope_re_eligible',
] as const

const notificationTypes: ReadonlySet<string> = new Set(NOTIFICATION_ALLOWED_TYPES)

// isDefaultFeedRow keeps the default view free of routine monitor noise even
// when the server sends a wider feed. Category chips opt out of this filter so
// an operator can still inspect deep changes explicitly.
export function isDefaultFeedRow(row: { source?: string; change_type?: string }): boolean {
  const type = row.change_type || ''
  // An actual HTTP status transition is a daily signal. Routine monitor diffs
  // stay out of the default view (A8).
  if (row.source === 'monitor') return type === 'http_change' || type === 'status_change'
  if (row.source === 'watch') return type === 'new_subdomain'
  if (row.source === 'watch_scope' || row.source === 'bounty') return isScopeEvent(row)
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

// Scope events carry JSON snapshots in old_value/new_value. The feed also
// ships legacy scope_landed bell rows. A dedicated renderer reads these fields
// once, so neither the card nor the Details drawer prints serialized JSON.
const SCOPE_EVENT_TYPES = new Set([
  'scope_landed', 'scope_proposed', 'scope_modified', 'scope_removed',
  'scope_rule_added', 'scope_rule_removed', 'scope_rejected',
])

export function isScopeEvent(row: { change_type?: string }): boolean {
  return !!row.change_type && SCOPE_EVENT_TYPES.has(row.change_type)
}

type ScopeSnapshot = Record<string, unknown>

// parseScopeSnapshot accepts any JSON object. Malformed or non-object input
// returns null, so callers fall back to the event label and asset identifier.
export function parseScopeSnapshot(raw: string | undefined | null): ScopeSnapshot | null {
  if (typeof raw !== 'string' || !raw.trim()) return null
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as ScopeSnapshot
    }
  } catch {
    // Fall through to the label/identifier fallback.
  }
  return null
}

const SCOPE_FIELD_LABELS: Record<string, string> = {
  identifier: 'Host',
  asset_type: 'Asset type',
  category: 'Category',
  in_scope: 'In scope',
  eligible_submission: 'Eligible submission',
  eligible_bounty: 'Eligible bounty',
  max_severity: 'Max severity',
  instruction: 'Instruction',
  active: 'Active',
  is_wildcard: 'Wildcard',
  program_id: 'Program',
  status: 'Status',
}

const SCOPE_VERBS: Record<string, string> = {
  scope_landed: 'Host landed.',
  scope_proposed: 'Scope proposed.',
  scope_modified: 'Scope modified.',
  scope_removed: 'Scope removed.',
  scope_rejected: 'Proposal rejected.',
  scope_re_eligible: 'Host re-eligible.',
  scope_rule_added: 'Rule added.',
  scope_rule_removed: 'Rule withdrawn.',
}

function scopeDisplayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }
  return String(value)
}

export interface ScopeChangedField {
  field: string
  before: string
  after: string
}

// scopeChangedFields compares only parsed snapshots. It never returns the raw
// JSON text, so the renderer cannot leak a serialized payload by accident.
export function scopeChangedFields(oldRaw: string | undefined, newRaw: string | undefined): ScopeChangedField[] {
  const before = parseScopeSnapshot(oldRaw)
  const after = parseScopeSnapshot(newRaw)
  if (!before || !after) return []
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
  const fields: ScopeChangedField[] = []
  for (const key of keys) {
    const oldValue = scopeDisplayValue(before[key])
    const newValue = scopeDisplayValue(after[key])
    if (oldValue === newValue) continue
    fields.push({ field: SCOPE_FIELD_LABELS[key] ?? key, before: oldValue, after: newValue })
  }
  return fields
}

// scopeIdentifier prefers the snapshot's identifier. Legacy rows and rows with
// an unparseable snapshot fall back to url, which the feed sets to the asset
// identifier.
export function scopeIdentifier(item: { url?: string; program_asset_id?: string; old_value?: string; new_value?: string }): string {
  const snapshots = [parseScopeSnapshot(item.new_value), parseScopeSnapshot(item.old_value)]
  for (const snapshot of snapshots) {
    const value = snapshot?.identifier
    if (typeof value === 'string' && value.trim()) return value
  }
  return (item.url || item.program_asset_id || '').trim()
}

// scopeEventSummary builds "api.example.test · Example Program · Host landed."
export function scopeEventSummary(
  item: { change_type?: string; url?: string; program_id?: string; program_asset_id?: string; old_value?: string; new_value?: string },
  programName?: string,
): string {
  const identifier = scopeIdentifier(item)
  const program = (programName || item.program_id || '').trim()
  const type = item.change_type || ''
  const verb = SCOPE_VERBS[type] || `${type.replace(/_/g, ' ')}.`
  return [identifier, program, verb].filter(Boolean).join(' · ')
}

const SCOPE_STATUS_LABELS: Record<string, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  superseded: 'Superseded',
}

export function scopeReviewLabel(status: string | undefined): string {
  if (!status) return ''
  return SCOPE_STATUS_LABELS[status] || status
}
