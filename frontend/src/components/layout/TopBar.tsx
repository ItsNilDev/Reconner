import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate, Link } from 'react-router-dom'
import { ws } from '../../lib/websocket'
import { useUIStore } from '../../store/ui'
import { notifications as notifApi, targets as targetsApi, type Notification } from '../../lib/api'
import type { Target } from '../../types'
import { cn, timeAgo, useDebouncedValue } from '../../lib/utils'
import { sevDot, openNotification, onNotificationsChanged, notifyNotificationsChanged } from '../../lib/notifications'
import { useUpdateCenter } from './UpdateCenter'

// Static labels for top-level route segments; `/targets/:id` resolves to the
// target name via a tiny in-memory cache so breadcrumbs read like
// "Targets › example.com" instead of a raw UUID.
const SEGMENT_LABEL: Record<string, string> = {
  targets: 'Targets', analyze: 'Guided Analyze', findings: 'Findings', changes: 'Changes', tasks: 'Scan activity', system: 'System & updates',
}

function useBreadcrumbs(): { label: string; to: string }[] {
  const { pathname } = useLocation()
  const [targetName, setTargetName] = useState<string | null>(null)
  const parts = pathname.split('/').filter(Boolean)

  // Resolve a target name when the path is /targets/:id.
  const targetId = parts[0] === 'targets' && parts[1] ? parts[1] : null
  useEffect(() => {
    if (!targetId) { setTargetName(null); return }
    let alive = true
    targetsApi.get(targetId).then(t => { if (alive) setTargetName(t.name || t.domain) }).catch(() => {})
    return () => { alive = false }
  }, [targetId])

  const crumbs: { label: string; to: string }[] = [{ label: 'Dashboard', to: '/' }]
  if (parts[0] && SEGMENT_LABEL[parts[0]]) crumbs.push({ label: SEGMENT_LABEL[parts[0]], to: `/${parts[0]}` })
  if (targetId) crumbs.push({ label: targetName || '…', to: `/targets/${targetId}` })
  return crumbs
}

// Global search — a lightweight command-palette-style target jump. Targets are
// fetched once and filtered client-side (debounced), so typing stays smooth
// even with thousands of targets. Enter jumps to the first match.
function GlobalSearch() {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [all, setAll] = useState<Target[]>([])
  const boxRef = useRef<HTMLDivElement | null>(null)
  const loadedRef = useRef(false)
  const loadSeqRef = useRef(0)
  const debounced = useDebouncedValue(q, 200)

  const refreshTargets = () => {
    const seq = ++loadSeqRef.current
    targetsApi.list().then(next => {
      if (seq === loadSeqRef.current) setAll(next || [])
    }).catch(() => {
      if (seq === loadSeqRef.current) loadedRef.current = false
    })
  }

  // Lazy-load the target list the first time the box is focused.
  const loadOnce = () => {
    if (loadedRef.current) return
    loadedRef.current = true
    refreshTargets()
  }

  useEffect(() => {
    const refresh = () => { if (loadedRef.current) refreshTargets() }
    const offs = ['target_created', 'target_updated', 'target_deleted'].map(event => ws.on(event, refresh))
    return () => offs.forEach(off => off())
  }, [])

  useEffect(() => {
    const onDoc = (e: MouseEvent) => { if (open && boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const results = useMemo(() => {
    const term = debounced.trim().toLowerCase()
    if (!term) return []
    return all.filter(t => (t.name || '').toLowerCase().includes(term) || (t.domain || '').toLowerCase().includes(term)).slice(0, 8)
  }, [debounced, all])

  const go = (t: Target) => { setOpen(false); setQ(''); nav(`/targets/${t.id}`) }

  return (
    <div className="relative hidden sm:block" ref={boxRef}>
      <div className="flex items-center gap-2 w-72 px-3.5 py-2 rounded-xl bg-black/20 border border-white/[.09] focus-within:border-accent/60 focus-within:bg-black/30 transition-all">
        <svg className="w-4 h-4 text-text-muted shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
          <circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" />
        </svg>
        <input name="reconner-target-search" autoComplete="off" value={q} onFocus={() => { loadOnce(); setOpen(true) }} onChange={e => { setQ(e.target.value); setOpen(true) }}
          onKeyDown={e => { if (e.key === 'Enter' && results[0]) go(results[0]); if (e.key === 'Escape') setOpen(false) }}
          placeholder="Search targets…" className="bg-transparent outline-none text-sm text-text-primary placeholder-text-muted w-full" />
      </div>
      {open && debounced.trim() && (
        <div className="absolute left-0 mt-2 w-80 max-h-80 overflow-y-auto rounded-xl border border-border bg-surface-2 shadow-2xl z-50">
          {results.length === 0
            ? <p className="text-xs text-text-muted text-center py-6">No targets match “{debounced.trim()}”.</p>
            : results.map(t => (
              <button key={t.id} onClick={() => go(t)}
                className="w-full text-left px-4 py-2.5 border-b border-border/60 last:border-0 hover:bg-white/[.04] transition-colors">
                <span className="block text-sm text-text-primary truncate">{t.name || t.domain}</span>
                {t.name && <span className="block text-[11px] text-text-muted truncate">{t.domain}</span>}
              </button>
            ))}
        </div>
      )}
    </div>
  )
}

export const TopBar = () => {
  const [connected, setConnected] = useState(() => ws.connected)
  const { toasts, removeToast, setMobileNavOpen } = useUIStore()
  const { info: updateInfo, visible: updateVisible, showDetails: showUpdateDetails } = useUpdateCenter()
  const navigate = useNavigate()
  const crumbs = useBreadcrumbs()

  const [items, setItems] = useState<Notification[]>([])
  const [unread, setUnread] = useState(0)
  const [open, setOpen] = useState(false)
  // Bell bucket: all | deep | watch | findings. The server maps the bucket to
  // the stored notification types, so a bucket is never empty because the
  // stored type is more granular than the bucket.
  const [bucket, setBucket] = useState<'all' | 'deep' | 'watch' | 'findings'>('all')
  const bellRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    setConnected(ws.connected)
    const offOpen = ws.on('open', () => setConnected(true))
    const offClose = ws.on('close', () => setConnected(false))
    return () => { offOpen(); offClose() }
  }, [])

  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout> | null = null
    let fallbackTimer: ReturnType<typeof setInterval> | null = null
    let inFlight = false
    let pending = false
    let controller: AbortController | null = null
    let hiddenAt: number | null = document.hidden ? Date.now() : null

    const runLoad = async () => {
      if (!alive) return
      if (inFlight) {
        pending = true
        return
      }
      inFlight = true
      pending = false
      const ac = new AbortController()
      controller = ac
      try {
        const r = await notifApi.list(bucket, ac.signal)
        if (alive && !ac.signal.aborted) {
          // The server maps each bucket to its stored notification types. The
          // bell shows every row it returns; the Changes feed has its own
          // allow-list for routine diffs.
          setItems(r.notifications || [])
          setUnread(r.unread || 0)
        }
      } catch {
        // A failed read (or abort on bucket change) must not fabricate an empty bell.
      } finally {
        if (controller === ac) controller = null
        inFlight = false
        if (alive && pending) {
          pending = false
          void runLoad()
        }
      }
    }

    const scheduleLoad = () => {
      if (!alive) return
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => {
        timer = null
        void runLoad()
      }, 1500)
    }

    const loadImmediate = () => {
      if (!alive) return
      if (timer) { clearTimeout(timer); timer = null }
      void runLoad()
    }

    const syncFallbackPoll = () => {
      const shouldPoll = !ws.connected && !document.hidden
      if (shouldPoll && !fallbackTimer) {
        fallbackTimer = setInterval(() => {
          if (!ws.connected && !document.hidden) void runLoad()
        }, 60 * 1000)
      } else if (!shouldPoll && fallbackTimer) {
        clearInterval(fallbackTimer)
        fallbackTimer = null
      }
    }

    const onVis = () => {
      if (document.hidden) {
        hiddenAt = Date.now()
        syncFallbackPoll()
        return
      }
      const hiddenMs = hiddenAt !== null ? Date.now() - hiddenAt : 0
      hiddenAt = null
      syncFallbackPoll()
      if (!ws.connected || hiddenMs > 30_000) loadImmediate()
    }

    loadImmediate()
    syncFallbackPoll()

    const offs = [
      ws.on('notification_created', scheduleLoad),
      ws.on('bounty_scope_change', scheduleLoad),
      ws.on('new_vuln_finding', scheduleLoad),
      ws.on('reconnected', loadImmediate),
      ws.on('open', syncFallbackPoll),
      ws.on('close', syncFallbackPoll),
      onNotificationsChanged(src => { if (src !== 'topbar') scheduleLoad() }),
    ]
    document.addEventListener('visibilitychange', onVis)
    return () => {
      alive = false
      clearTimeout(timer ?? undefined)
      clearInterval(fallbackTimer ?? undefined)
      controller?.abort()
      offs.forEach(off => off())
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [bucket])

  // Close the dropdown on an outside click.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (open && bellRef.current && !bellRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const markAllRead = async () => {
    try {
      // Scope the bulk write to the open bucket. The server also scopes it,
      // and a failed write must not clear local state (B3).
      const res = await notifApi.markRead([], bucket)
      setItems(current => current.map(n => ({ ...n, is_read: true })))
      // The server counts unread across all buckets. Use its value, or the
      // badge would return on the next poll with unread items elsewhere.
      setUnread(typeof res?.unread === 'number' ? res.unread : 0)
      notifyNotificationsChanged('topbar')
    } catch { /* keep the previous read state on failure */ }
  }

  const openNotif = (n: Notification) => {
    setOpen(false)
    if (!n.is_read) {
      setItems(current => current.map(item => item.id === n.id ? { ...item, is_read: true } : item))
      setUnread(current => Math.max(0, current - 1))
    }
    openNotification(n, navigate, notifApi.markRead, 'topbar')
  }

  return (
    <>
      <header className="app-topbar relative z-40 h-[76px] flex items-center justify-between gap-3 px-3 sm:px-6 xl:px-8 shrink-0">
        {/* Breadcrumbs */}
        <div className="flex items-center gap-2 min-w-0">
          <button type="button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"
            className="grid place-items-center w-9 h-9 rounded-lg border border-border text-text-secondary hover:text-text-primary hover:bg-white/[.05] md:hidden shrink-0">
            <span className="space-y-1" aria-hidden>{[0,1,2].map(i => <span key={i} className="block w-4 h-px bg-current" />)}</span>
          </button>
        <nav className="flex items-center gap-1.5 text-sm min-w-0" aria-label="Breadcrumb">
          {crumbs.map((c, i) => (
            <span key={c.to} className="flex items-center gap-1.5 min-w-0">
              {i > 0 && <span className="text-text-muted/60 shrink-0">›</span>}
              {i === crumbs.length - 1
                ? <span className="text-text-primary font-medium truncate">{c.label}</span>
                : <Link to={c.to} className="text-text-secondary hover:text-text-primary transition-colors truncate">{c.label}</Link>}
            </span>
          ))}
        </nav>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <GlobalSearch />

          {/* Notifications bell */}
          <div className="relative" ref={bellRef}>
            <button onClick={() => setOpen(o => !o)} title="Notifications"
              className="relative p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[.06] transition-colors">
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              {(unread + (updateVisible ? 1 : 0)) > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-severity-critical text-white text-[10px] font-bold grid place-items-center">
                  {(unread + (updateVisible ? 1 : 0)) > 99 ? '99+' : unread + (updateVisible ? 1 : 0)}
                </span>
              )}
            </button>

            {open && (
              <div className="fixed sm:absolute left-3 right-3 sm:left-auto sm:right-0 top-16 sm:top-auto sm:mt-2 sm:w-80 max-h-[70dvh] overflow-hidden flex flex-col rounded-xl border border-border bg-surface-2 shadow-2xl z-[110]">
                <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-b border-border shrink-0">
                  <span className="text-sm font-semibold">Notifications</span>
                  <div className="flex items-center gap-2">
                    <select value={bucket} onChange={e => setBucket(e.target.value as typeof bucket)}
                      title="Filter notifications"
                      className="bg-surface-1 border border-border rounded text-[11px] text-text-secondary px-1.5 py-0.5">
                      <option value="all">All</option>
                      <option value="deep">Deep</option>
                      <option value="watch">Watch</option>
                      <option value="findings">Findings</option>
                    </select>
                    {(items.some(n => !n.is_read) || (bucket === 'all' && unread > 0)) && (
                      <button onClick={markAllRead} className="text-[11px] text-accent hover:underline">Mark all read</button>
                    )}
                  </div>
                </div>
                <div className="flex-1 min-h-0 overflow-y-auto">
                  {updateVisible && updateInfo && (
                    <button onClick={() => { setOpen(false); showUpdateDetails() }}
                      className="w-full text-left px-4 py-3 border-b border-accent/20 bg-accent/[.06] hover:bg-accent/[.10] transition-colors flex gap-2.5">
                      <span className="mt-1.5 w-2 h-2 rounded-full shrink-0 bg-accent animate-pulse" />
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-semibold text-text-primary">Reconner v{updateInfo.latest} is available</span>
                        <span className="block text-[11px] text-text-secondary">Review changes and safe update commands.</span>
                        <span className="block text-[10px] text-accent mt-1">Open release center →</span>
                      </span>
                    </button>
                  )}
                  {items.length === 0 && !updateVisible ? (
                    <p className="text-xs text-text-muted text-center py-8">No notifications yet.</p>
                  ) : items.map(n => (
                    <button key={n.id} onClick={() => openNotif(n)}
                      className={cn('w-full text-left px-4 py-2.5 border-b border-border/60 hover:bg-white/[.04] transition-colors flex gap-2.5',
                        !n.is_read && 'bg-accent/[.05]')}>
                      <span className={cn('mt-1.5 w-2 h-2 rounded-full shrink-0', sevDot[n.severity] || 'bg-accent')} />
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-semibold text-text-primary truncate">{n.title}</span>
                        {n.body && <span className="block text-[11px] text-text-secondary break-words line-clamp-2">{n.body}</span>}
                        <span className="block text-[10px] text-text-muted mt-0.5">{timeAgo(n.created_at)}</span>
                      </span>
                    </button>
                  ))}
                </div>
                <div className="shrink-0 border-t border-border bg-surface-2">
                  <Link to="/changes" onClick={() => setOpen(false)}
                    className="block px-4 py-2.5 text-center text-[11px] text-accent hover:bg-white/[.04]">
                    View all changes →
                  </Link>
                </div>
              </div>
            )}
          </div>

          <div className={cn('flex items-center gap-2 text-xs font-medium px-2 sm:px-3 py-1.5 rounded-full border',
            connected
              ? 'text-severity-low border-severity-low/25 bg-severity-low/10'
              : 'text-text-muted border-white/10 bg-white/5')}>
            <span className={connected ? 'dot-online' : 'dot-offline'}/>
            <span className="hidden sm:inline">{connected ? 'Live' : 'Offline'}</span>
          </div>
        </div>
      </header>

      <div className="fixed bottom-5 right-5 z-[110] flex flex-col gap-2 pointer-events-none">
        {toasts.map(t => (
          <div key={t.id} className={cn('flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg text-sm pointer-events-auto min-w-64 max-w-sm',
            t.type === 'success' && 'bg-surface-3 border-severity-low/30 text-severity-low',
            t.type === 'error' && 'bg-surface-3 border-severity-critical/30 text-severity-critical',
            t.type === 'warning' && 'bg-surface-3 border-severity-medium/30 text-severity-medium',
            t.type === 'info' && 'bg-surface-3 border-accent/30 text-accent',
          )}>
            {/* min-w-0 + break lets a long message wrap/clamp instead of stretching the
                toast across the whole viewport (a pasted 700-IP scope did exactly that). */}
            <span className="flex-1 min-w-0 break-words line-clamp-4 max-h-40 overflow-hidden">{t.message}</span>
            <button onClick={() => removeToast(t.id)} className="opacity-60 hover:opacity-100 shrink-0">✕</button>
          </div>
        ))}
      </div>
    </>
  )
}
