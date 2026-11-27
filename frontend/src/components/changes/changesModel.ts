import { diffWordsWithSpace } from 'diff'
import type { ChangeCategory, ChangeEntry } from '../../types'

export type ChangeTabFilter = 'all' | 'hosts' | 'status' | 'title' | 'tech' | 'scope' | 'security_js'

export const CHANGE_TABS: { id: ChangeTabFilter; label: string; category?: string; title?: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'hosts', label: 'New hosts', category: 'hosts', title: 'New subdomains & hosts (breadth + deep)' },
  { id: 'status', label: 'Status & Redirects', category: 'status', title: 'HTTP status code transitions and redirect destination changes' },
  { id: 'title', label: 'Titles', category: 'title', title: 'Page title changes across breadth, deep, and monitor scans' },
  { id: 'tech', label: 'Tech', category: 'tech', title: 'Server and technology stack changes' },
  { id: 'scope', label: 'Scope', category: 'scope', title: 'Program and watch scope changes' },
  { id: 'security_js', label: 'Scripts & Security', category: 'security,headers,scripts', title: 'JavaScript, stylesheet, and security header changes' },
]

// Exact mirror of changeCategoryExpr in internal/api/changes_handlers.go.
// Keep both lists in sync: the feed ships a `category` column computed there.
export const CATEGORY_BY_TYPE: Record<string, ChangeCategory> = {
  status_change: 'http',
  http_change: 'http',
  redirect_change: 'http',
  page_change: 'http',
  content_change: 'http',
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
  out_of_scope: 'assets',
  watch_failed: 'alerts',
  watch_kind_conflict: 'alerts',
  monitor_failed: 'alerts',
  monitor_escalation_started: 'alerts',
  scan_auto_paused: 'alerts',
  bounty_scope_change: 'alerts',
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

export function parseFormattedStatusTitle(value: string): { code?: number; title?: string } | null {
  const match = /^status=(\d+)\s+title=(.*)$/s.exec(value || '')
  if (!match) return null
  const parsed = Number(match[1])
  const code = Number.isInteger(parsed) && parsed >= 100 && parsed <= 599 ? parsed : undefined
  return { code, title: match[2] }
}

export function parseStatusTransition(oldValue: string, newValue: string): { oldCode?: number; newCode?: number } {
  // Mirror changesStatusCodeExpr in changes_handlers.go: require a leading
  // "status=NNN " prefix (optionally after a YYYY-MM-DD date prefix) so raw
  // page titles containing "status=200 " cannot spoof a status transition.
  const pick = (value: string) => {
    const match = /^(?:\d{4}-\d{2}-\d{2}\s+)?status=([1-5]\d{2})\s/.exec(value || '')
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
  'scope_re_eligible', 'out_of_scope',
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
  out_of_scope: 'Removed from eligible scope.',
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
  item: { change_type?: string; url?: string; program_id?: string; program_asset_id?: string; old_value?: string; new_value?: string; source?: string; scope_status?: string },
  programName?: string,
): string {
  const identifier = scopeIdentifier(item)
  const program = (programName || item.program_id || '').trim()
  const type = item.change_type || ''
  let verb = SCOPE_VERBS[type] || `${type.replace(/_/g, ' ')}.`
  if (type === 'scope_landed') {
    if (item.source === 'bounty') {
      if (item.scope_status === 'pending') verb = 'Scope proposed.'
      else if (item.scope_status === 'superseded') verb = 'Proposal superseded.'
      else if (item.scope_status === 'rejected') verb = 'Proposal dismissed.'
      else verb = 'Scope added.'
    } else if (item.source === 'watch_scope') {
      verb = 'Host landed.'
    }
  }
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
