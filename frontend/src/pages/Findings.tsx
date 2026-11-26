import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { findings as findingsApi, targets as targetsApi, type AllFinding } from '../lib/api'
import { useUIStore } from '../store/ui'
import { timeAgo, truncate, cn } from '../lib/utils'
import { CopyButton } from '../components/ui'

const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const
type Sev = typeof SEVS[number]

const PAGE_LIMIT = 200

const SOURCE_OPTIONS: [string, string][] = [
  ['', 'All sources'],
  ['native', 'Native'],
  ['nuclei', 'Nuclei'],
  ['backup', 'Backup'],
  ['open_redirect', 'Open redirect'],
  ['js_secret', 'JS secret'],
]

const SOURCE_META: Record<string, { label: string; cls: string }> = {
  native: { label: 'Native', cls: 'bg-accent/15 text-accent border-accent/30' },
  nuclei: { label: 'Nuclei', cls: 'bg-purple-500/15 text-purple-300 border-purple-500/30' },
  backup: { label: 'Backup', cls: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30' },
  open_redirect: { label: 'Redirect', cls: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' },
  js_secret: { label: 'JS', cls: 'bg-severity-high/15 text-severity-high border-severity-high/30' },
}

const sevText: Record<string, string> = {
  critical: 'text-severity-critical', high: 'text-severity-high',
  medium: 'text-severity-medium', low: 'text-severity-low', info: 'text-text-muted',
}
const sevBadge: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
  info: 'bg-white/5 text-text-muted border-border',
}

const rowKey = (f: AllFinding) => `${f.source || 'native'}:${f.id}`

export default function Findings() {
  const nav = useNavigate()
  const { addToast } = useUIStore()
  const [rows, setRows] = useState<AllFinding[]>([])
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const querySeqRef = useRef(0)
  const rowsRef = useRef<AllFinding[]>([])
  const totalRef = useRef(0)
  const [status, setStatus] = useState<'finding' | 'candidate'>('finding')
  const [sevFilter, setSevFilter] = useState<Sev | null>(null)
  const [sourceFilter, setSourceFilter] = useState('')
  const [targetFilter, setTargetFilter] = useState('')
  const [search, setSearch] = useState('')
  const [debouncedQ, setDebouncedQ] = useState('')
  const [apiTargets, setApiTargets] = useState<{ id: string; label: string }[]>([])
  const [err, setErr] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [triageBusy, setTriageBusy] = useState<Record<string, string>>({})
  const [confirmedIds, setConfirmedIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(search.trim()), 200)
    return () => clearTimeout(t)
  }, [search])

  useEffect(() => {
    let cancelled = false
    targetsApi.list()
      .then(list => {
        if (cancelled || !Array.isArray(list)) return
        const opts = list
          .filter(t => t && typeof t.id === 'string' && !('target_id' in t))
          .map(t => ({ id: t.id, label: t.name ? `${t.name} (${t.domain})` : t.domain }))
        setApiTargets(opts)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    const seq = ++querySeqRef.current
    setLoading(true)
    setLoadingMore(false)
    setHasMore(false)
    setErr('')
    setExpanded(null)
    findingsApi.allPage({
      status,
      severity: sevFilter || undefined,
      source: sourceFilter || undefined,
      target_id: targetFilter || undefined,
      q: debouncedQ || undefined,
      page: 1,
      limit: PAGE_LIMIT,
    })
      .then(res => {
        if (seq !== querySeqRef.current) return
        const items = res.data || []
        rowsRef.current = items
        totalRef.current = res.total
        setRows(items)
        setTotal(res.total)
        setHasMore(items.length >= PAGE_LIMIT && items.length < res.total)
      })
      .catch(e => { if (seq === querySeqRef.current) setErr(e?.message || 'Failed to load findings') })
      .finally(() => { if (seq === querySeqRef.current) setLoading(false) })
    return () => { querySeqRef.current++ }
  }, [status, sevFilter, sourceFilter, targetFilter, debouncedQ])

  const loadMore = async () => {
    if (loadingMore || !hasMore) return
    const seq = querySeqRef.current
    setLoadingMore(true)
    try {
      const res = await findingsApi.allPage({
        status,
        severity: sevFilter || undefined,
        source: sourceFilter || undefined,
        target_id: targetFilter || undefined,
        q: debouncedQ || undefined,
        offset: rowsRef.current.length,
        limit: PAGE_LIMIT,
      })
      if (seq !== querySeqRef.current) return
      const fetched = res.data || []
      const prev = rowsRef.current
      const seen = new Set(prev.map(rowKey))
      const extra = fetched.filter(item => !seen.has(rowKey(item)))
      const nextRows = [...prev, ...extra]
      rowsRef.current = nextRows
      totalRef.current = res.total
      setRows(nextRows)
      setTotal(res.total)
      setHasMore(fetched.length >= PAGE_LIMIT && extra.length > 0 && nextRows.length < res.total)
    } catch (e) {
      if (seq !== querySeqRef.current) return
      addToast('error', e instanceof Error ? e.message : 'Failed to load more findings')
    } finally {
      if (seq === querySeqRef.current) setLoadingMore(false)
    }
  }

  const handleTriage = async (f: AllFinding, decision: 'confirmed' | 'false_positive') => {
    const key = rowKey(f)
    const seq = querySeqRef.current
    setTriageBusy(prev => ({ ...prev, [key]: decision }))
    try {
      await findingsApi.setTriage(f.target_id, f.id, decision)
      if (decision === 'false_positive') {
        if (seq === querySeqRef.current) {
          const prev = rowsRef.current
          const nextRows = prev.filter(r => rowKey(r) !== key)
          const removed = prev.length - nextRows.length
          const nextTotal = Math.max(0, totalRef.current - removed)
          rowsRef.current = nextRows
          totalRef.current = nextTotal
          setRows(nextRows)
          setTotal(nextTotal)
          if (nextRows.length >= nextTotal) setHasMore(false)
          if (expanded === key) setExpanded(null)
        }
        addToast('info', 'Marked as false positive')
      } else {
        setConfirmedIds(prev => { const next = new Set(prev); next.add(key); return next })
        addToast('success', 'Finding confirmed')
      }
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Failed to update triage')
    } finally {
      setTriageBusy(prev => { const next = { ...prev }; delete next[key]; return next })
    }
  }

  const targetOptions = useMemo(() => {
    const map = new Map<string, string>()
    for (const t of apiTargets) map.set(t.id, t.label)
    for (const f of rows) {
      if (f.target_id && !map.has(f.target_id)) map.set(f.target_id, f.domain || f.target_id)
    }
    return [...map.entries()]
      .map(([id, label]) => ({ id, label }))
      .sort((a, b) => a.label.localeCompare(b.label))
  }, [apiTargets, rows])

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of rows) c[f.severity?.toLowerCase()] = (c[f.severity?.toLowerCase()] || 0) + 1
    return c
  }, [rows])

  const shown = useMemo(
    () => sevFilter ? rows.filter(f => f.severity?.toLowerCase() === sevFilter) : rows,
    [rows, sevFilter])

  const hasFilters = Boolean(search || sourceFilter || targetFilter || sevFilter)

  return (
    <div className="space-y-5">
      <div className="flex items-end gap-3 flex-wrap">
        <div><p className="page-kicker">Evidence desk</p><h1 className="mt-1 text-3xl font-semibold tracking-[-.04em]">Findings</h1><p className="page-lede mt-1">Verified issues and candidates across every project.</p></div>
        <div className="ml-auto flex items-center gap-1 text-xs">
          <button onClick={() => { setStatus('finding'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'finding' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Confirmed
          </button>
          <button onClick={() => { setStatus('candidate'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'candidate' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Needs Review
          </button>
        </div>
      </div>

      {/* compact filter bar */}
      <div className="card p-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search host, URL, type, parameter…"
          aria-label="Search findings"
          className="h-9 flex-1 min-w-0 bg-surface-alt border border-border rounded-lg px-3 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent/60"
        />
        <select
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value)}
          aria-label="Filter by source"
          className="h-9 sm:w-40 bg-surface-alt border border-border rounded-lg px-2.5 text-xs text-text-primary outline-none focus:border-accent/60"
        >
          {SOURCE_OPTIONS.map(([val, label]) => (
            <option key={val} value={val} className="bg-surface-3">{label}</option>
          ))}
        </select>
        <select
          value={targetFilter}
          onChange={e => setTargetFilter(e.target.value)}
          aria-label="Filter by target"
          className="h-9 sm:w-52 bg-surface-alt border border-border rounded-lg px-2.5 text-xs text-text-primary outline-none focus:border-accent/60"
        >
          <option value="" className="bg-surface-3">All targets</option>
          {targetOptions.map(t => (
            <option key={t.id} value={t.id} className="bg-surface-3">{t.label}</option>
          ))}
        </select>
        {hasFilters && (
          <button
            type="button"
            onClick={() => { setSearch(''); setSourceFilter(''); setTargetFilter(''); setSevFilter(null) }}
            className="text-xs text-accent hover:underline px-1.5 shrink-0"
          >
            Clear
          </button>
        )}
      </div>

      {/* severity summary — click to filter */}
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setSevFilter(null)}
          className={cn('px-3 py-2 rounded-lg border text-xs font-medium', !sevFilter ? 'border-accent text-accent' : 'border-border text-text-muted')}>
          All {!sevFilter && <span className="tabular-nums">{total}</span>}
        </button>
        {SEVS.map(s => (
          <button key={s} onClick={() => setSevFilter(sevFilter === s ? null : s)}
            disabled={!sevFilter && !hasMore && !counts[s]}
            className={cn('px-3 py-2 rounded-lg border text-xs font-medium capitalize disabled:opacity-40',
              sevFilter === s ? 'border-accent' : 'border-border', sevText[s])}>
            {s}{!sevFilter ? <> <span className="tabular-nums">{counts[s] || 0}</span></> : sevFilter === s ? <> <span className="tabular-nums">{total}</span></> : null}
          </button>
        ))}
      </div>

      {err && <div className="card p-4 text-sm text-severity-high">{err}</div>}

      <div className="card overflow-hidden" style={{ padding: 0 }}>
        {loading ? (
          <p className="text-sm text-text-muted p-8 text-center">Loading findings…</p>
        ) : shown.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-text-secondary text-sm mb-1">
              {hasFilters ? 'No findings match these filters.' : status === 'finding' ? 'No confirmed findings yet.' : 'Nothing awaiting review.'}
            </p>
            <p className="text-text-muted text-xs">
              {hasFilters
                ? 'Try clearing or widening your search, severity, source, or target filter.'
                : 'Findings appear here as scans confirm them. Start a scan from a target to populate this view.'}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {['Severity', 'Type', 'Target', 'URL', 'Parameter', 'Payload', 'Conf.', 'Found'].map(h => (
                      <th key={h} className="table-header text-left">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shown.map(f => {
                    const key = rowKey(f)
                    const href = `/targets/${f.target_id}?tab=${f.source_tab || (status === 'candidate' ? 'candidates' : 'vulns')}`
                    const isOpen = expanded === key
                    const isNative = !f.source || f.source === 'native'
                    const srcMeta = f.source ? SOURCE_META[f.source] : undefined
                    const stop = (e: React.MouseEvent) => e.stopPropagation()
                    return (
                    <Fragment key={key}>
                    <tr onClick={() => nav(href)}
                      className="border-b border-border/50 last:border-0 hover:bg-surface-3/50 transition-colors cursor-pointer">
                      <td className="table-cell">
                        <span className={cn('px-2 py-0.5 rounded border text-[10px] font-semibold uppercase', sevBadge[f.severity?.toLowerCase()] || sevBadge.info)}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="table-cell font-mono text-xs">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span>{f.type}</span>
                          {f.source && (
                            <span className={cn('px-1.5 py-0.5 rounded border text-[9px] font-sans font-semibold uppercase tracking-wide', srcMeta?.cls || 'bg-white/5 text-text-muted border-border')}>
                              {srcMeta?.label || f.source}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="table-cell text-xs text-text-secondary">{f.domain}</td>
                      <td className="table-cell font-mono text-xs text-text-muted" title={f.url}>{truncate(f.url, 60)}</td>
                      <td className="table-cell font-mono text-xs">{f.parameter || '—'}</td>
                      <td className="table-cell font-mono text-xs max-w-[220px]">
                        {f.payload ? (
                          <div className="flex items-center gap-1.5" onClick={stop}>
                            <span className="text-severity-medium truncate" title={f.payload}>{truncate(f.payload, 40)}</span>
                            <CopyButton text={f.payload} />
                            <button
                              onClick={() => setExpanded(isOpen ? null : key)}
                              className="text-text-muted hover:text-accent text-[10px] shrink-0">
                              {isOpen ? 'hide' : 'PoC'}
                            </button>
                          </div>
                        ) : f.evidence ? (
                          <button onClick={e => { stop(e); setExpanded(isOpen ? null : key) }}
                            className="text-text-muted hover:text-accent text-[10px]">
                            {isOpen ? 'hide' : 'evidence'}
                          </button>
                        ) : isNative ? (
                          <button onClick={e => { stop(e); setExpanded(isOpen ? null : key) }}
                            className="text-text-muted hover:text-accent text-[10px]">
                            {isOpen ? 'hide' : 'triage'}
                          </button>
                        ) : <span className="text-text-muted">—</span>}
                      </td>
                      <td className="table-cell text-xs tabular-nums">{f.confidence || '—'}</td>
                      <td className="table-cell text-xs text-text-muted whitespace-nowrap">{timeAgo(f.created_at)}</td>
                    </tr>
                    {isOpen && (
                      <tr className="border-b border-border/50 bg-surface-3/30" onClick={stop}>
                        <td colSpan={8} className="table-cell">
                          <div className="space-y-2 py-1">
                            {f.payload && (
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">Payload</div>
                                <div className="flex items-start gap-1">
                                  <pre className="flex-1 font-mono text-[10px] text-severity-medium whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded">{f.payload}</pre>
                                  <CopyButton text={f.payload} />
                                </div>
                              </div>
                            )}
                            {f.evidence && (
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">Evidence</div>
                                <pre className="font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-40 overflow-auto">{f.evidence}</pre>
                              </div>
                            )}
                            <div className="flex items-center gap-2 flex-wrap pt-0.5">
                              <button onClick={() => nav(href)} className="text-[11px] text-accent hover:underline">
                                Open in target →
                              </button>
                              {isNative && (
                                <div className="ml-auto flex items-center gap-1.5">
                                  <button
                                    type="button"
                                    disabled={!!triageBusy[key]}
                                    onClick={() => handleTriage(f, 'confirmed')}
                                    className={cn(
                                      'px-2 py-0.5 rounded border text-[11px] font-medium transition-colors disabled:opacity-50',
                                      confirmedIds.has(key)
                                        ? 'border-severity-low/50 bg-severity-low/15 text-severity-low'
                                        : 'border-severity-low/30 text-severity-low hover:bg-severity-low/10',
                                    )}
                                  >
                                    {triageBusy[key] === 'confirmed' ? 'Confirming…' : confirmedIds.has(key) ? 'Confirmed' : 'Confirm'}
                                  </button>
                                  <button
                                    type="button"
                                    disabled={!!triageBusy[key]}
                                    onClick={() => handleTriage(f, 'false_positive')}
                                    className="px-2 py-0.5 rounded border border-severity-critical/30 text-severity-critical hover:bg-severity-critical/10 text-[11px] font-medium transition-colors disabled:opacity-50"
                                  >
                                    {triageBusy[key] === 'false_positive' ? 'Marking…' : 'Mark FP'}
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                    </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
            {(hasMore || shown.length < total) && (
              <div className="border-t border-border p-3 flex items-center justify-center gap-3">
                <span className="text-xs text-text-muted tabular-nums">Showing {shown.length} of {total}</span>
                {hasMore && (
                  <button
                    type="button"
                    onClick={loadMore}
                    disabled={loadingMore}
                    className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-50"
                  >
                    {loadingMore ? 'Loading…' : 'Load more'}
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
