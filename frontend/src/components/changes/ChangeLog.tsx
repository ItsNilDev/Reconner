import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { bounty, changes, targets as targetsApi, watchApi } from '../../lib/api'
import type { ChangeEntry, Target, WatchRound } from '../../types'
import { Badge, Button, CopyButton, Drawer, Empty, SkeletonRows } from '../ui'
import { cn, safeHref, timeAgo } from '../../lib/utils'
import { ws } from '../../lib/websocket'
import { notifyNotificationsChanged } from '../../lib/notifications'
import {
  CHANGE_TABS, changeBadgeVariant, changeHosts, isScopeEvent,
  scopeEventSummary, type ChangeTabFilter,
} from './changesModel'
import InlineChangeDiff from './InlineChangeDiff'
import ScopeEventView from './ScopeEventView'
import { ChangeDiffViewer } from '../targets/ChangeDiffViewer'

type DiffView = {
  targetId: string
  url: string
  kind: 'css' | 'js'
  expectedOldHash?: string
  expectedNewHash?: string
}

function isDiffableItem(item: ChangeEntry): boolean {
  return item.source === 'monitor' && (item.change_type === 'css_change' || item.change_type === 'js_change') && !!item.url
}

// 'initial' shows a skeleton and resets paging. 'refresh' keeps the current
// rows on screen and only shows a subtle hint while new data loads.
type LoadMode = 'initial' | 'refresh'

const PAGE = 200

const TIME_FILTERS = [
  { id: '0', label: 'All time' },
  { id: '12', label: '12h' },
  { id: '24', label: '24h' },
  { id: '168', label: '7d' },
  { id: '720', label: '30d' },
  { id: '2160', label: '90d' },
  { id: '-1', label: 'Custom…' },
]

type SourceFilter = '' | 'monitor' | 'watch' | 'watch_scope' | 'bounty' | 'alerts'

const SOURCE_FILTERS: { id: SourceFilter; label: string }[] = [
  { id: '', label: 'Any source' },
  { id: 'monitor', label: 'Deep monitor' },
  { id: 'watch', label: 'Watch round' },
  { id: 'watch_scope', label: 'Watch scope' },
  { id: 'bounty', label: 'Program scope' },
  { id: 'alerts', label: 'System alerts' },
]

const SOURCE_FILTER_LABELS: Record<Exclude<SourceFilter, ''>, string> = {
  monitor: 'Deep monitor',
  watch: 'Watch round',
  watch_scope: 'Watch scope',
  bounty: 'Program scope',
  alerts: 'System alerts',
}

const STATUS_CLASS_FILTERS = [
  { id: '2', label: '2xx' },
  { id: '3', label: '3xx' },
  { id: '4', label: '4xx' },
  { id: '5', label: '5xx' },
]

const FIELD_LABELS: Record<string, string> = {
  status_change: 'Status code',
  http_change: 'HTTP / page',
  http_service_removed: 'Service removed',
  new_http_service: 'New service',
  redirect_change: 'Redirect',
  page_change: 'Page',
  content_change: 'Content',
  js_change: 'JavaScript',
  css_change: 'Stylesheet',
  tech_change: 'Technologies',
  new_subdomain: 'New host',
  subdomain_removed: 'Host removed',
  host_status_change: 'Host status',
  scope_landed: 'Scope landed',
  scope_modified: 'Scope modified',
  scope_removed: 'Scope removed',
  scope_re_eligible: 'Scope re-eligible',
  bounty_scope_change: 'Bounty scope change',
  security_header_removed: 'Security header',
  watch_failed: 'Watch failed',
  watch_kind_conflict: 'Watch conflict',
  monitor_failed: 'Monitor failed',
  monitor_escalation_started: 'Escalation',
  scan_auto_paused: 'Auto paused',
}

const ROUND_DOT: Record<string, string> = {
  running: 'bg-severity-medium',
  finished: 'bg-severity-low',
  completed: 'bg-severity-low',
  failed: 'bg-severity-critical',
  cancelled: 'bg-text-muted',
  interrupted: 'bg-text-muted',
}

function fieldLabel(changeType: string): string {
  if (!changeType) return 'CHANGE'
  if (FIELD_LABELS[changeType]) return FIELD_LABELS[changeType].toUpperCase()
  if (changeType.startsWith('security:')) {
    return changeType.slice('security:'.length).replace(/_/g, ' ').toUpperCase()
  }
  return changeType.replace(/_/g, ' ').toUpperCase()
}

function sinceFor(hours: string, custom: string): string {
  if (hours === '-1') return custom ? new Date(custom).toISOString() : ''
  if (hours === '0' || !hours) return ''
  const ms = Number(hours) * 3600_000
  if (!Number.isFinite(ms)) return ''
  return new Date(Date.now() - ms).toISOString()
}

// Free-text inputs are debounced so each keystroke does not trigger a full
// reload and paging reset. The committed value still feeds params(), so any
// real filter change behaves exactly as before.
function useDebounced<T>(value: T, delay: number): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return settled
}

// Keep only whole codes in the real HTTP range. Invalid tokens are dropped,
// so a half-typed input never turns into a partial or truncated code.
function parseStatusCodes(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const token of raw.split(',')) {
    const code = token.trim()
    if (!/^[1-5][0-9]{2}$/.test(code) || seen.has(code)) continue
    seen.add(code)
    out.push(code)
  }
  return out
}

function fmtDate(value: string): string {
  if (!value) return '—'
  const iso = value.includes('T') ? value : value.replace(' ', 'T') + 'Z'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

interface ChangeCard {
  key: string
  target_id: string
  target_name: string
  url: string
  task_id: string
  source: string
  seen: boolean
  detected_at: string
  items: ChangeEntry[]
}

// One card per host per scan. task_id identifies a watch round; rows without
// one use the exact timestamp, which groups rows written by the same pass.
function groupIntoCards(rows: ChangeEntry[]): ChangeCard[] {
  const map = new Map<string, ChangeCard>()
  for (const r of rows) {
    const key = `${r.target_id}\u0000${r.url}\u0000${r.task_id || r.detected_at}`
    let card = map.get(key)
    if (!card) {
      card = {
        key, target_id: r.target_id, target_name: r.target_name, url: r.url,
        task_id: r.task_id || '', source: r.source, seen: false,
        detected_at: r.detected_at, items: [],
      }
      map.set(key, card)
    }
    card.items.push(r)
    if (r.detected_at > card.detected_at) card.detected_at = r.detected_at
  }
  for (const card of map.values()) card.seen = card.items.every(i => i.seen)
  return [...map.values()].sort((a, b) => b.detected_at.localeCompare(a.detected_at))
}

function NewHostsSection({ items }: { items: ChangeEntry[] }) {
  const sections = items
    .map(item => ({ hosts: changeHosts(item), meta: item.metadata }))
    .filter(g => Array.isArray(g.hosts) && g.hosts.length > 0)
  if (sections.length === 0) return null
  const shown: string[] = []
  let total = 0
  let truncated = false
  for (const g of sections) {
    const hosts = g.hosts as string[]
    shown.push(...hosts)
    total += typeof g.meta?.total === 'number' ? g.meta.total : hosts.length
    if (g.meta?.truncated === true) truncated = true
  }
  return (
    <div className="mt-4 rounded-lg border border-accent/25 bg-accent/[.06] p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">
        {total} new subdomain(s)
      </p>
      <div className="mt-2 max-h-64 space-y-1 overflow-y-auto font-mono text-xs text-text-primary">
        {sections.map((g, gi) => (
          <div key={gi}>
            {(typeof g.meta?.status === 'number' || typeof g.meta?.in_scope === 'boolean' || !!g.meta?.server) && (
              <div className="mb-0.5 text-[10px] text-text-muted">
                {typeof g.meta?.status === 'number' && <span>HTTP {g.meta.status} </span>}
                {!!g.meta?.server && <span>{String(g.meta.server)} </span>}
                {g.meta?.in_scope === true && <span className="text-accent">· in scope</span>}
                {g.meta?.in_scope === false && <span>· out of scope</span>}
              </div>
            )}
            {Array.isArray(g.meta?.members) && g.meta.members.length > 0 ? (
              (g.meta.members as { host?: string; in_scope?: boolean }[]).map((m, i) => (
                <div key={`${m.host}-${gi}-${i}`} className="break-all">
                  {m.host}
                  {typeof m.in_scope === 'boolean' && (
                    <span className={m.in_scope ? 'ml-1 text-accent' : 'ml-1 text-text-muted'}>
                      {m.in_scope ? '· in scope' : '· out of scope'}
                    </span>
                  )}
                </div>
              ))
            ) : (
              (g.hosts as string[]).map((h, i) => <div key={`${h}-${gi}-${i}`} className="break-all">{h}</div>)
            )}
          </div>
        ))}
      </div>
      {truncated && (
        <p className="mt-2 text-[10px] text-text-muted">
          Showing first {shown.length} of {total} stored host names.
        </p>
      )}
    </div>
  )
}

function SourceBadge({ source }: { source: string }) {
  const map: Record<string, { label: string; className: string }> = {
    watch: { label: 'Watch', className: 'border-accent/50 bg-accent/10 text-accent' },
    monitor: { label: 'Deep', className: 'border-border text-text-muted' },
    watch_scope: { label: 'Watch scope', className: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium' },
    bounty: { label: 'Bounty', className: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium' },
    notification: { label: 'Bell', className: 'border-severity-low/40 bg-severity-low/10 text-severity-low' },
  }
  const s = map[source] || { label: source, className: 'border-border text-text-muted' }
  return (
    <span className={cn('rounded-full border px-1.5 py-0.5 text-[10px]', s.className)}>
      {s.label}
    </span>
  )
}

interface Props {
  targetId?: string
  compact?: boolean
  initialEventId?: string
  initialQuery?: string
  onClearEventId?: () => void
}

export default function ChangeLog({ targetId, compact, initialEventId, initialQuery = '', onClearEventId }: Props) {
  const [hours, setHours] = useState('0')
  const [customSince, setCustomSince] = useState('')
  const [tabFilter, setTabFilter] = useState<ChangeTabFilter>('all')
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [statusClasses, setStatusClasses] = useState<Set<string>>(() => new Set<string>())
  const [statusCodes, setStatusCodes] = useState('')
  const debouncedCodes = useDebounced(statusCodes, 300)
  const [q, setQ] = useState(initialQuery)
  const debouncedQ = useDebounced(q, 300)
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('')
  const [severity, setSeverity] = useState('')
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [selectedTaskId, setSelectedTaskId] = useState('')
  const [hideSeen, setHideSeen] = useState(false)
  const [viewMode, setViewMode] = useState<'signals' | 'all'>('signals')
  const [activeEventId, setActiveEventId] = useState(initialEventId || '')
  const [rows, setRows] = useState<ChangeEntry[]>([])
  const [rounds, setRounds] = useState<WatchRound[]>([])
  const [targetList, setTargetList] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [serverTotal, setServerTotal] = useState(0)
  const [programNames, setProgramNames] = useState<Record<string, string>>({})
  const [detail, setDetail] = useState<ChangeCard | null>(null)
  const handledEventRef = useRef('')

  useEffect(() => { setQ(initialQuery) }, [initialQuery])
  useEffect(() => { setActiveEventId(initialEventId || '') }, [initialEventId])
  const [diffView, setDiffView] = useState<DiffView | null>(null)

  const requestSeq = useRef(0)
  const pageCount = useRef(1)
  const reloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Coalescing state. A refresh triggered while one is running is collapsed
  // into a single follow-up, so overlapping WS events cannot stack queries.
  const inFlight = useRef(false)
  const pendingMode = useRef<LoadMode | null>(null)
  const hasLoaded = useRef(false)
  const loadRef = useRef<((mode?: LoadMode) => Promise<void>) | null>(null)

  useEffect(() => {
    if (targetId) return
    let alive = true
    targetsApi.list().then(list => { if (alive) setTargetList(list || []) }).catch(() => {})
    return () => { alive = false }
  }, [targetId])

  // The default view is the real-events feed. An explicit category, source,
  // severity, status, text filter or selected round is a deliberate request to
  // see the wider history. Compute this from the SAME values passed to
  // buildParams, so reads and Mark all read agree even inside the debounce
  // window (A11, review findings #2 and #6).
  const isDefaultView = useCallback((searchText: string, codesText: string) =>
    viewMode === 'signals' && tabFilter === 'all' && !sourceFilter && !severity && !selectedTaskId && !activeEventId &&
    !searchText.trim() && statusClasses.size === 0 &&
    parseStatusCodes(codesText).length === 0,
    [viewMode, tabFilter, sourceFilter, severity, selectedTaskId, statusClasses, activeEventId])

  // Build query params from explicit text values. Reads pass the debounced
  // values, while writes (mark-all-read) pass the raw values so a click before
  // the debounce settles still targets exactly the rows currently on screen.
  const buildParams = useCallback((searchText: string, codesText: string): Record<string, string> => {
    const p: Record<string, string> = {}
    if (isDefaultView(searchText, codesText)) p.default_view = '1'
    if (hideSeen) p.hide_seen = '1'
    const since = sinceFor(hours, customSince)
    if (since) p.since = since
    const tabDef = CHANGE_TABS.find(t => t.id === tabFilter)
    if (sourceFilter === 'alerts') {
      p.category = 'alerts'
    } else {
      if (tabDef?.category) p.category = tabDef.category
      if (sourceFilter) p.source = sourceFilter
    }
    if (statusClasses.size) p.status_class = [...statusClasses].join(',')
    const codes = parseStatusCodes(codesText)
    if (codes.length) p.status_code = codes.join(',')
    if (searchText.trim()) p.q = searchText.trim()
    if (severity) p.severity = severity
    if (selectedTaskId) p.task_id = selectedTaskId
    if (activeEventId) p.event_id = activeEventId
    const t = targetId || selectedTargetId
    if (t) p.target_id = t
    return p
  }, [hours, customSince, tabFilter, statusClasses, sourceFilter, severity, selectedTaskId, targetId, selectedTargetId, activeEventId, hideSeen, isDefaultView])
  const params = useCallback((): Record<string, string> => buildParams(debouncedQ, debouncedCodes),
    [buildParams, debouncedQ, debouncedCodes])

  useEffect(() => {
    bounty.list().then(r => {
      const names: Record<string, string> = {}
      for (const p of r.programs || []) names[p.id] = p.name
      setProgramNames(names)
    }).catch(() => {})
  }, [])

  const load = useCallback(async (mode: LoadMode = 'refresh') => {
    if (inFlight.current) {
      if (mode === 'initial' || pendingMode.current === null) pendingMode.current = mode
      return
    }
    inFlight.current = true
    const first = mode === 'initial' || !hasLoaded.current
    if (first) setLoading(true)
    else setRefreshing(true)
    const seq = ++requestSeq.current
    setError('')
    if (mode === 'initial') pageCount.current = 1
    const p = params()
    const roundTarget = targetId || selectedTargetId
    // Total is captured here and only committed after the stale-response
    // check. Setting it inside the fetch callback let a superseded response
    // overwrite the total for the current filter set.
    let fetchedTotal: number | null = null
    try {
      const [changeRows, roundRows] = await Promise.all([
        targetId
          ? Promise.all(
            Array.from({ length: pageCount.current }, (_, i) =>
              changes.forTargetPage(targetId, { ...p, page: String(i + 1), limit: String(PAGE) })),
          ).then(pages => {
            const merged: ChangeEntry[] = []
            const ids = new Set<string>()
            for (const page of pages) {
              fetchedTotal = page.total
              for (const row of page.data) if (!ids.has(row.id)) { ids.add(row.id); merged.push(row) }
            }
            return merged
          })
          : Promise.all(
            Array.from({ length: pageCount.current }, (_, i) =>
              changes.listPage({ ...p, page: String(i + 1), limit: String(PAGE) })),
          ).then(pages => {
            const merged: ChangeEntry[] = []
            const ids = new Set<string>()
            for (const page of pages) {
              fetchedTotal = page.total
              for (const row of page.data) {
                if (!ids.has(row.id)) { ids.add(row.id); merged.push(row) }
              }
            }
            return merged
          }),
        watchApi.rounds(roundTarget ? { target_id: roundTarget, limit: 20 } : { limit: 20 }),
      ])
      // Only the newest response may replace the rows. A stale response is
      // still cleared below, so it can never leave the skeleton stuck.
      if (seq !== requestSeq.current) return
      if (fetchedTotal !== null) setServerTotal(fetchedTotal)
      setRows(changeRows)
      setRounds(roundRows.data)
    } catch (e) {
      if (seq === requestSeq.current) setError(e instanceof Error ? e.message : 'Failed to load changes')
    } finally {
      inFlight.current = false
      hasLoaded.current = true
      if (seq === requestSeq.current) {
        setLoading(false)
        setRefreshing(false)
      }
      const next = pendingMode.current
      pendingMode.current = null
      if (next) void loadRef.current?.(next)
    }
  }, [params, targetId, selectedTargetId])
  loadRef.current = load

  useEffect(() => { void load('initial') }, [load])

  useEffect(() => {
    const schedule = (payload?: unknown) => {
      if (targetId) {
        const p = payload as { target_id?: string } | undefined
        if (p?.target_id && p.target_id !== targetId) return
      }
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
      reloadTimer.current = setTimeout(() => { void load('refresh') }, 2500)
    }
    // task_progress fires per module and scope_landed is already folded into
    // the bounty scope feed. Neither should re-query the whole feed.
    const offs = [
      ws.on('task_finished', schedule),
      ws.on('changes_written', schedule),
      ws.on('bounty_scope_change', schedule),
    ]
    return () => {
      offs.forEach(off => off())
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
    }
  }, [load, targetId])

  useEffect(() => {
    if (!activeEventId || handledEventRef.current === activeEventId) return
    const found = rows.find(r => r.id === activeEventId)
    if (!found) return
    handledEventRef.current = activeEventId
    setDetail(groupIntoCards([found])[0] || null)
  }, [activeEventId, rows])

  const loadMore = async () => {
    const next = pageCount.current + 1
    const seq = ++requestSeq.current
    setLoading(true)
    try {
      const res = targetId
        ? await changes.forTargetPage(targetId, { ...params(), page: String(next), limit: String(PAGE) })
        : await changes.listPage({ ...params(), page: String(next), limit: String(PAGE) })
      if (seq !== requestSeq.current) return
      pageCount.current = next
      setServerTotal(res.total)
      setRows(prev => {
        const ids = new Set(prev.map(r => r.id))
        const added = res.data.filter(r => !ids.has(r.id))
        return added.length ? [...prev, ...added] : prev
      })
    } catch (e) {
      if (seq === requestSeq.current) setError(e instanceof Error ? e.message : 'Failed to load more changes')
    } finally {
      if (seq === requestSeq.current) setLoading(false)
    }
  }

  const selectTab = (id: ChangeTabFilter) => {
    if (activeEventId) {
      handledEventRef.current = ''
      setActiveEventId('')
      setDetail(null)
      onClearEventId?.()
    }
    setTabFilter(id)
    if (sourceFilter === 'alerts') setSourceFilter('')
    if (id !== 'all') setViewMode('all')
  }

  const handleSourceChange = (next: SourceFilter) => {
    setSourceFilter(next)
    if (next === 'alerts') setTabFilter('all')
  }

  const resetAdvancedFilters = () => {
    setStatusClasses(new Set<string>())
    setStatusCodes('')
    setSeverity('')
    setSourceFilter('')
    setSelectedTaskId('')
  }

  const selectDailySignals = () => {
    setViewMode('signals')
    setTabFilter('all')
    setQ('')
    resetAdvancedFilters()
  }

  const toggleStatusClass = (cls: string) => {
    setStatusClasses(prev => {
      const next = new Set(prev)
      if (next.has(cls)) next.delete(cls)
      else next.add(cls)
      return next
    })
  }

  const applySeen = (ids: string[], seen: boolean) => {
    const idSet = new Set(ids)
    setRows(prev => prev.map(r => idSet.has(r.id) ? { ...r, seen } : r))
    setDetail(prev => {
      if (!prev) return prev
      const items = prev.items.map(i => idSet.has(i.id) ? { ...i, seen } : i)
      return { ...prev, items, seen: items.every(i => i.seen) }
    })
  }

  const toggleCardSeen = async (card: ChangeCard) => {
    const seen = !card.seen
    const ids = card.items.map(i => i.id)
    try {
      await changes.setSeen(ids, seen)
      applySeen(ids, seen)
      notifyNotificationsChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update read state')
    }
  }

  const markAllRead = async () => {
    try {
      // Use raw text, not the debounced values, so a click right after typing
      // marks only the rows the user currently sees.
      const res = await changes.markAllSeen(buildParams(q, statusCodes))
      if (res.updated > 0) await load('refresh')
      notifyNotificationsChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to mark all read')
    }
  }

  const cards = useMemo(() => groupIntoCards(rows), [rows])
  const parsedStatusCodes = useMemo(() => parseStatusCodes(statusCodes), [statusCodes])
  const advancedFilterCount =
    (statusClasses.size > 0 ? 1 : 0) +
    (parsedStatusCodes.length > 0 ? 1 : 0) +
    (severity ? 1 : 0) +
    (sourceFilter ? 1 : 0)
  const isSignalsActive = isDefaultView(q, statusCodes)
  const selectedRound = rounds.find(r => r.id === selectedTaskId)

  return (
    <div className={cn('space-y-3', compact && 'space-y-2')}>
      {activeEventId && (
        <div className="flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-xs text-text-primary">
          Showing focused event
          <button type="button" className="text-accent hover:underline" onClick={() => {
            handledEventRef.current = ''
            setActiveEventId('')
            setDetail(null)
            onClearEventId?.()
          }}>Show all changes</button>
        </div>
      )}
      {/* Row 1: Primary bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="segmented-control" role="group" aria-label="Feed mode">
          <button type="button" onClick={selectDailySignals} className={cn(isSignalsActive && 'active')}>
            Daily signals
          </button>
          <button type="button" onClick={() => setViewMode('all')} className={cn(!isSignalsActive && 'active')}>
            All history
          </button>
        </div>
        <input
          className="input w-48 py-1 text-xs"
          placeholder="Search changes…"
          value={q}
          onChange={e => setQ(e.target.value)}
          title="Search URL, target, change type, before and after values"
        />
        <select
          aria-label="Time range"
          className="input w-auto py-1 text-xs"
          value={hours}
          onChange={e => setHours(e.target.value)}
        >
          {TIME_FILTERS.map(f => (
            <option key={f.id} value={f.id}>{f.label}</option>
          ))}
        </select>
        {hours === '-1' && (
          <input
            aria-label="Custom start time"
            className="input w-auto py-1 text-xs"
            type="datetime-local"
            value={customSince}
            onChange={e => setCustomSince(e.target.value)}
          />
        )}
        {!targetId && (
          <select
            aria-label="Target filter"
            className="input w-auto py-1 text-xs"
            value={selectedTargetId}
            onChange={e => setSelectedTargetId(e.target.value)}
          >
            <option value="">All targets</option>
            {targetList.map(t => (
              <option key={t.id} value={t.id}>{t.name || t.domain}</option>
            ))}
          </select>
        )}
        <button
          type="button"
          aria-pressed={hideSeen}
          onClick={() => setHideSeen(v => !v)}
          className={cn(
            'rounded-lg border px-2.5 py-1 text-[11px] transition',
            hideSeen
              ? 'border-accent bg-accent/15 text-accent'
              : 'border-border text-text-muted hover:text-text-primary',
          )}
        >
          Unread
        </button>
        <button
          type="button"
          aria-expanded={filtersOpen}
          onClick={() => setFiltersOpen(v => !v)}
          className={cn(
            'rounded-lg border px-2.5 py-1 text-[11px] transition',
            filtersOpen || advancedFilterCount > 0
              ? 'border-accent bg-accent/15 text-accent'
              : 'border-border text-text-muted hover:text-text-primary',
          )}
        >
          {advancedFilterCount > 0 ? `Filters · ${advancedFilterCount}` : 'Filters'}
        </button>
        {refreshing && !loading && (
          <span className="ml-auto text-[10px] text-text-muted">Refreshing…</span>
        )}
        <button
          type="button"
          onClick={() => void load('refresh')}
          disabled={loading || refreshing}
          className={cn(
            'text-[11px] text-text-muted hover:text-text-primary disabled:opacity-50',
            !(refreshing && !loading) && 'ml-auto',
          )}
        >
          Refresh
        </button>
      </div>

      {/* Row 2: 7 mutually-exclusive type pills + Mark all read */}
      <div className="flex flex-wrap items-center gap-1.5 border-y border-white/[.06] py-2">
        {CHANGE_TABS.map(tab => (
          <button
            key={tab.id}
            type="button"
            title={tab.title}
            onClick={() => selectTab(tab.id)}
            className={cn(
              'rounded-full border px-2.5 py-1 text-[11px] transition',
              tabFilter === tab.id && sourceFilter !== 'alerts'
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-border text-text-muted hover:text-text-primary',
            )}
          >
            {tab.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => void markAllRead()}
          className="ml-auto text-[11px] text-accent hover:underline"
        >
          Mark all read
        </button>
      </div>

      {/* Active advanced filter pills */}
      {(advancedFilterCount > 0 || selectedTaskId) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {statusClasses.size > 0 && (
            <button
              type="button"
              aria-label="Remove status class filter"
              onClick={() => setStatusClasses(new Set<string>())}
              className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
            >
              Class: {[...statusClasses].map(c => `${c}xx`).join(', ')} <span aria-hidden="true">×</span>
            </button>
          )}
          {parsedStatusCodes.length > 0 && (
            <button
              type="button"
              aria-label="Remove status codes filter"
              onClick={() => setStatusCodes('')}
              className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
            >
              Codes: {parsedStatusCodes.join(', ')} <span aria-hidden="true">×</span>
            </button>
          )}
          {severity && (
            <button
              type="button"
              aria-label="Remove severity filter"
              onClick={() => setSeverity('')}
              className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
            >
              Severity: {severity} <span aria-hidden="true">×</span>
            </button>
          )}
          {sourceFilter && (
            <button
              type="button"
              aria-label="Remove source filter"
              onClick={() => setSourceFilter('')}
              className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
            >
              Source: {SOURCE_FILTER_LABELS[sourceFilter]} <span aria-hidden="true">×</span>
            </button>
          )}
          {selectedTaskId && (
            <button
              type="button"
              aria-label="Remove watch round filter"
              onClick={() => setSelectedTaskId('')}
              className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
            >
              Round: {selectedRound ? (selectedRound.target_name || selectedRound.target_id) : selectedTaskId.slice(0, 12)} <span aria-hidden="true">×</span>
            </button>
          )}
          <button
            type="button"
            onClick={resetAdvancedFilters}
            className="text-[11px] text-text-muted hover:text-text-primary hover:underline"
          >
            Reset filters
          </button>
        </div>
      )}

      {/* Collapsible advanced filters panel */}
      {filtersOpen && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5 rounded-xl border border-border bg-surface-2/60 p-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[10px] uppercase tracking-wide text-text-muted">Status codes</span>
            {STATUS_CLASS_FILTERS.map(f => (
              <button
                key={f.id}
                type="button"
                onClick={() => toggleStatusClass(f.id)}
                className={cn(
                  'rounded-full border px-2.5 py-1 text-[11px] transition',
                  statusClasses.has(f.id)
                    ? 'border-accent bg-accent/15 text-accent'
                    : 'border-border text-text-muted hover:text-text-primary',
                )}
              >
                {f.label}
              </button>
            ))}
            <span className="ml-1 text-[10px] text-text-muted">Codes</span>
            <input
              className="input w-28 py-1 text-xs"
              placeholder="200,403"
              value={statusCodes}
              onChange={e => setStatusCodes(e.target.value)}
              title="Exact status codes, comma separated (100-599)"
            />
            {(tabFilter === 'hosts' || tabFilter === 'tech' || tabFilter === 'scope' || tabFilter === 'security_js') && (
              <span className="ml-1 text-[10px] text-text-muted">
                Matches rows carrying HTTP status codes
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Severity"
              className="input w-auto py-1 text-xs"
              value={severity}
              onChange={e => setSeverity(e.target.value)}
            >
              <option value="">Any severity</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select
              aria-label="Source"
              className="input w-auto py-1 text-xs"
              value={sourceFilter}
              onChange={e => handleSourceChange(e.target.value as SourceFilter)}
            >
              {SOURCE_FILTERS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </div>
          <button
            type="button"
            onClick={resetAdvancedFilters}
            className="ml-auto text-[11px] text-text-muted hover:text-text-primary hover:underline"
          >
            Reset filters
          </button>
        </div>
      )}
      {/* Slim watch round strip. Status word stays visible, not just the dot. */}
      {rounds.length > 0 && (
        <div className="flex items-center gap-1.5 overflow-x-auto py-1.5">
          <span className="shrink-0 mr-1 text-[10px] uppercase tracking-wide text-text-muted">Breadth rounds</span>
          {rounds.slice(0, 20).map(r => (
            <button
              key={r.id}
              type="button"
              onClick={() => setSelectedTaskId(prev => prev === r.id ? '' : r.id)}
              className={cn(
                'shrink-0 rounded-full border px-2.5 py-1 text-[11px] transition',
                selectedTaskId === r.id
                  ? 'border-accent bg-accent/15 text-accent'
                  : 'border-border text-text-muted hover:text-text-primary',
              )}
              title={`${r.target_name} · ${r.status} · ${r.change_count} change(s)`}
            >
              <span className={cn('mr-1 inline-block h-1.5 w-1.5 rounded-full', ROUND_DOT[r.status] || 'bg-text-muted')} />
              {r.target_name || r.target_id} · {timeAgo(r.finished_at || r.started_at)} · {r.change_count}
              <span className="ml-1 opacity-70">{r.status}</span>
            </button>
          ))}
          {selectedTaskId && (
            <button type="button" onClick={() => setSelectedTaskId('')} className="shrink-0 text-[10px] text-accent hover:underline">
              Clear
            </button>
          )}
        </div>
      )}

      {error && <p className="rounded-lg border border-severity-medium/30 bg-severity-medium/10 px-3 py-2 text-xs text-severity-medium">{error}</p>}

      {/* The change log feed */}
      <div className="overflow-hidden rounded-xl border border-white/[.06] bg-white/[.02]">
        {loading ? (
          <div className="py-2"><SkeletonRows rows={8} cols={3} /></div>
        ) : cards.length === 0 ? (
          <Empty message={hideSeen ? 'All changes are marked as seen.' : 'No changes recorded yet.'} />
        ) : (
          cards.map(card => {
            const href = safeHref(card.url)
            return (
              <div
                key={card.key}
                className={cn('border-b border-white/[.05] px-3 py-3 last:border-0', card.seen && 'opacity-40')}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="shrink-0 text-[10px] tabular-nums text-text-muted">{fmtDate(card.detected_at)}</span>
                  <SourceBadge source={card.source} />
                  {!targetId && (
                    <span className="max-w-[160px] shrink-0 truncate text-xs text-text-primary" title={card.target_name || card.target_id}>
                      {card.target_name || card.target_id || '—'}
                    </span>
                  )}
                  {href && (
                    <a
                      href={href}
                      target="_blank"
                      rel="noreferrer"
                      className="max-w-[420px] min-w-0 truncate text-xs text-accent hover:underline"
                      title={card.url}
                    >
                      {card.url}
                    </a>
                  )}
                  {!href && card.url && (
                    <span className="max-w-[420px] min-w-0 truncate text-xs text-text-muted" title={card.url}>
                      {card.url}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => void toggleCardSeen(card)}
                    className="ml-auto shrink-0 rounded border border-border px-2 py-0.5 text-[10px] text-text-muted hover:text-text-primary"
                  >
                    {card.seen ? 'unmark' : 'mark'}
                  </button>
                </div>

                <div className="mt-2 space-y-1.5 pl-1">
                  {card.items.map((item, i) => {
                    if (isScopeEvent(item)) {
                      return <ScopeEventView key={`${item.id}-${i}`} item={item} variant="card" programName={item.program_id ? programNames[item.program_id] : undefined} />
                    }
                    const hosts = changeHosts(item)
                    return (
                      <div key={`${item.id}-${i}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
                        <span className="w-32 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-text-muted">
                          {fieldLabel(item.change_type)}
                        </span>
                        {hosts && hosts.length > 0 ? (
                          <span className="flex flex-wrap items-center gap-1">
                            {hosts.slice(0, 5).map(host => (
                              <span key={host} className="rounded border border-border px-1 font-mono text-[10px] text-text-primary">{host}</span>
                            ))}
                            {hosts.length > 5 && <button type="button" onClick={() => setDetail(card)} className="text-[10px] text-accent hover:underline">+{hosts.length - 5} more</button>}
                            <CopyButton text={hosts.join('\n')} />
                            {typeof item.metadata?.status === 'number' && <Badge variant="info">HTTP {item.metadata.status}</Badge>}
                            {item.metadata?.in_scope === true && <Badge variant="low">in scope</Badge>}
                          </span>
                        ) : (
                          <InlineChangeDiff oldValue={item.old_value} newValue={item.new_value} changeType={item.change_type} oldStatus={item.old_status} newStatus={item.new_status} />
                        )}
                        <Badge variant={changeBadgeVariant(item)}>{item.severity}</Badge>
                        {isDiffableItem(item) && (
                          <button
                            type="button"
                            onClick={() => setDiffView({
                              targetId: item.target_id || card.target_id,
                              url: item.url,
                              kind: item.change_type === 'css_change' ? 'css' : 'js',
                              expectedOldHash: item.old_value,
                              expectedNewHash: item.new_value,
                            })}
                            className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                          >
                            Diff
                          </button>
                        )}
                      </div>
                    )
                  })}
                </div>

                <div className="mt-2 flex items-center gap-3 pl-1 text-[10px] text-text-muted">
                  <button type="button" onClick={() => setDetail(card)} className="text-accent hover:underline">
                    Details
                  </button>
                  <span className="tabular-nums">{card.items.length} change(s)</span>
                </div>
              </div>
            )
          })
        )}
      </div>

      {rows.length < serverTotal && (
        <div className="flex justify-center">
          <Button size="sm" variant="ghost" onClick={() => void loadMore()} disabled={loading}>
            Load {Math.min(PAGE, serverTotal - rows.length)} more
          </Button>
        </div>
      )}

      {/* Detail drawer (portaled into document.body) */}
      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detail ? (
          detail.items[0] && isScopeEvent(detail.items[0])
            ? scopeEventSummary(detail.items[0], programNames[detail.items[0]?.program_id || ''])
            : fieldLabel(detail.items[0]?.change_type || '')
        ) : undefined}
        subtitle={detail ? (detail.url || detail.target_name) : undefined}
        footer={detail ? (
          <div className="flex items-center gap-3">
            {detail.target_id && (
              <Link
                to={`/targets/${detail.target_id}`}
                className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent hover:bg-accent/20"
              >
                Open target →
              </Link>
            )}
            <button
              type="button"
              onClick={() => void toggleCardSeen(detail)}
              className="text-xs text-text-muted hover:text-text-primary"
            >
              {detail.seen ? 'Mark unread' : 'Mark read'}
            </button>
          </div>
        ) : undefined}
      >
        {detail && (
          <>
            <dl className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Target</dt>
                <dd className="truncate">{detail.target_name || detail.target_id}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Detected</dt>
                <dd className="tabular-nums">{fmtDate(detail.detected_at)}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Source</dt>
                <dd><SourceBadge source={detail.source} /></dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Round</dt>
                <dd className="font-mono text-[10px]">{detail.task_id ? detail.task_id.slice(0, 12) : '—'}</dd>
              </div>
            </dl>

            <NewHostsSection items={detail.items} />

            <div className="mt-4 space-y-3">
              {detail.items.map((item, i) => {
                if (isScopeEvent(item)) {
                  return <ScopeEventView key={`${item.id}-${i}`} item={item} variant="details" programName={item.program_id ? programNames[item.program_id] : undefined} />
                }
                return (
                <div key={`${item.id}-${i}`} className="rounded-lg border border-white/[.06] bg-white/[.02] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">
                      {fieldLabel(item.change_type)} · {item.severity}
                    </p>
                    {isDiffableItem(item) && (
                      <button
                        type="button"
                        onClick={() => setDiffView({
                          targetId: item.target_id || detail.target_id,
                          url: item.url,
                          kind: item.change_type === 'css_change' ? 'css' : 'js',
                          expectedOldHash: item.old_value,
                          expectedNewHash: item.new_value,
                        })}
                        className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                      >
                        Diff
                      </button>
                    )}
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <p className="text-[10px] text-text-muted">Before</p>
                      <p className="mt-0.5 break-all whitespace-pre-wrap font-mono text-severity-medium">{item.old_value || '∅'}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-text-muted">After</p>
                      <p className="mt-0.5 break-all whitespace-pre-wrap font-mono text-severity-low">{item.new_value || '∅'}</p>
                    </div>
                  </div>
                  {item.url && (
                    <p className="mt-2 flex items-center gap-1 text-[10px] text-text-muted">
                      <span className="max-w-[260px] truncate" title={item.url}>{item.url}</span>
                      <CopyButton text={item.url} />
                    </p>
                  )}
                  {item.metadata && Object.keys(item.metadata).length > 0 && (
                    <pre className="mt-2 max-h-32 overflow-auto rounded bg-black/30 p-2 text-[10px] text-text-muted">
                      {JSON.stringify(item.metadata, null, 2)}
                    </pre>
                  )}
                </div>
                )
              })}
            </div>
          </>
        )}
      </Drawer>

      {diffView && (
        <ChangeDiffViewer
          targetId={diffView.targetId}
          url={diffView.url}
          kind={diffView.kind}
          expectedOldHash={diffView.expectedOldHash}
          expectedNewHash={diffView.expectedNewHash}
          onClose={() => setDiffView(null)}
        />
      )}
    </div>
  )
}
