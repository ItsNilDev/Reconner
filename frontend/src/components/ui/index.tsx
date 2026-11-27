import React, { forwardRef, useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'

export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(' ')
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary'|'secondary'|'ghost'|'danger'
  size?: 'sm'|'md'|'lg'
  loading?: boolean
}
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant='secondary', size='md', loading, children, className, disabled, ...props }, ref) => {
    const v = { primary:'btn-primary', secondary:'btn-secondary', ghost:'btn-ghost', danger:'btn-danger' }
    const s = { sm:'text-xs px-2.5 py-1', md:'text-sm px-3 py-1.5', lg:'text-sm px-4 py-2' }
    return (
      <button ref={ref} className={cn('btn', v[variant], s[size], className)} disabled={disabled || loading} {...props}>
        {loading && <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>}
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'

export const Badge = ({ children, variant='neutral', className }: { children: React.ReactNode; variant?: string; className?: string }) => {
  const v: Record<string,string> = {
    neutral:'badge-neutral', success:'badge-low', warning:'badge-medium', error:'badge-critical', info:'badge-info',
    critical:'badge-critical', high:'badge-high', medium:'badge-medium', low:'badge-low', unknown:'badge-neutral',
  }
  return <span className={cn('badge', v[variant] || 'badge-neutral', className)}>{children}</span>
}

export const Spinner = ({ className }: { className?: string }) => (
  <span className={cn('reconner-loader', className || 'w-6 h-6')} role="status" aria-label="Loading">
    <span className="reconner-loader-ring" />
    <span className="reconner-loader-sweep" />
    <span className="reconner-loader-core" />
  </span>
)

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> { label?: string; error?: string }
export const Input = forwardRef<HTMLInputElement, InputProps>(({ label, error, className, id, ...props }, ref) => {
  const generatedID = useId()
  const inputID = id || generatedID
  const errorID = error ? `${inputID}-error` : undefined
  return (
    <div className="w-full">
      {label && <label className="label" htmlFor={inputID}>{label}</label>}
      <input ref={ref} id={inputID} aria-invalid={error ? true : undefined} aria-describedby={errorID}
        className={cn('input', error ? 'border-severity-critical' : undefined, className)} {...props}/>
      {error && <p id={errorID} className="mt-1 text-xs text-severity-critical">{error}</p>}
    </div>
  )
})
Input.displayName = 'Input'

let scrollLockCount = 0
let savedBodyOverflow = ''
let savedWorkspaceEl: HTMLElement | null = null
let savedWorkspaceOverflow = ''

// Ref-counted scroll lock covering both document.body and the main workspace
// container so nested overlays (e.g. Drawer -> ChangeDiffViewer Modal) never
// unlock scrolling prematurely when the inner layer closes.
export function acquireScrollLock(): () => void {
  if (scrollLockCount === 0) {
    savedBodyOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    savedWorkspaceEl = document.querySelector<HTMLElement>('main.workspace')
    if (savedWorkspaceEl) {
      savedWorkspaceOverflow = savedWorkspaceEl.style.overflow
      savedWorkspaceEl.style.overflow = 'hidden'
    }
  }
  scrollLockCount++
  let released = false
  return () => {
    if (released) return
    released = true
    scrollLockCount = Math.max(0, scrollLockCount - 1)
    if (scrollLockCount === 0) {
      document.body.style.overflow = savedBodyOverflow
      if (savedWorkspaceEl) {
        savedWorkspaceEl.style.overflow = savedWorkspaceOverflow
        savedWorkspaceEl = null
      }
    }
  }
}

type EscapeEntry = { close: () => void }
const escapeStack: EscapeEntry[] = []
let escapeListenerAttached = false

function handleGlobalEscape(event: KeyboardEvent) {
  if (event.key !== 'Escape' || event.defaultPrevented) return
  const top = escapeStack[escapeStack.length - 1]
  if (top) {
    event.preventDefault()
    top.close()
  }
}

export function registerEscapeClose(onClose: () => void): () => void {
  const entry: EscapeEntry = { close: onClose }
  escapeStack.push(entry)
  if (!escapeListenerAttached) {
    document.addEventListener('keydown', handleGlobalEscape)
    escapeListenerAttached = true
  }
  let unregistered = false
  return () => {
    if (unregistered) return
    unregistered = true
    const idx = escapeStack.indexOf(entry)
    if (idx !== -1) escapeStack.splice(idx, 1)
    if (escapeStack.length === 0 && escapeListenerAttached) {
      document.removeEventListener('keydown', handleGlobalEscape)
      escapeListenerAttached = false
    }
  }
}

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function getFocusableElements(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    el => !el.closest('[hidden], [inert]') && el.getAttribute('aria-hidden') !== 'true',
  )
}

export const Modal = ({ open, onClose, title, children, footer, width='md', bodyClassName }: {
  open: boolean
  onClose: () => void
  title?: string
  children: React.ReactNode
  footer?: React.ReactNode
  width?: 'sm'|'md'|'lg'|'xl'|'2xl'
  bodyClassName?: string
}) => {
  const w = { sm:'max-w-sm', md:'max-w-md', lg:'max-w-2xl', xl:'max-w-4xl', '2xl':'max-w-6xl' }
  const titleID = useId()
  const bodyRef = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  useEffect(() => {
    if (!open) return
    const releaseLock = acquireScrollLock()
    const unregisterEscape = registerEscapeClose(() => onCloseRef.current())
    if (bodyRef.current) bodyRef.current.scrollTop = 0
    return () => {
      unregisterEscape()
      releaseLock()
    }
  }, [open])
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center overflow-hidden p-2 sm:p-4">
      <button type="button" aria-label="Close dialog" tabIndex={-1} className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose}/>
      <div role="dialog" aria-modal="true" aria-labelledby={title ? titleID : undefined}
        className={cn('relative flex min-h-0 max-h-[calc(100dvh-1rem)] w-full flex-col overflow-hidden rounded-2xl border border-border bg-surface-2 shadow-2xl sm:max-h-[calc(100dvh-2rem)]', w[width])}>
        {title && <div className="flex items-center justify-between gap-3 px-4 sm:px-5 py-4 border-b border-border shrink-0"><h2 id={titleID} className="text-base font-semibold truncate min-w-0" title={title}>{title}</h2><button type="button" onClick={onClose} aria-label="Close" className="grid place-items-center w-8 h-8 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[.05] transition-colors shrink-0">✕</button></div>}
        <div ref={bodyRef} data-modal-scroll-region className={cn('min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 sm:p-5', bodyClassName)}>{children}</div>
        {footer && <div className="shrink-0 border-t border-border bg-surface-2 px-4 py-3 sm:px-5">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

export const Drawer = ({ open, onClose, title, subtitle, ariaLabel, children, footer, width = 'md' }: {
  open: boolean
  onClose: () => void
  title?: React.ReactNode
  subtitle?: React.ReactNode
  ariaLabel?: string
  children: React.ReactNode
  footer?: React.ReactNode
  width?: 'md' | 'lg'
}) => {
  const titleID = useId()
  const drawerRef = useRef<HTMLElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  useEffect(() => {
    if (!open) return
    const releaseLock = acquireScrollLock()
    const unregisterEscape = registerEscapeClose(() => onCloseRef.current())
    if (bodyRef.current) bodyRef.current.scrollTop = 0

    const prevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const drawer = drawerRef.current
    if (drawer) {
      const focusables = getFocusableElements(drawer)
      ;(focusables[0] ?? drawer).focus()
    }

    const handleTab = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return
      const currentDrawer = drawerRef.current
      if (!currentDrawer) return
      const topDialog = Array.from(document.querySelectorAll('[role="dialog"]')).pop()
      if (topDialog && topDialog !== currentDrawer) return

      const focusables = getFocusableElements(currentDrawer)
      if (focusables.length === 0) {
        event.preventDefault()
        currentDrawer.focus()
        return
      }
      const active = document.activeElement
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (event.shiftKey) {
        if (!active || !currentDrawer.contains(active) || active === first || active === currentDrawer) {
          event.preventDefault()
          last.focus()
        }
      } else if (!active || !currentDrawer.contains(active) || active === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', handleTab)
    return () => {
      document.removeEventListener('keydown', handleTab)
      unregisterEscape()
      releaseLock()
      if (prevFocused?.isConnected) prevFocused.focus()
    }
  }, [open])
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-[100] flex justify-end overflow-hidden">
      <button
        type="button"
        aria-label="Close panel"
        tabIndex={-1}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside
        ref={drawerRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleID : undefined}
        aria-label={!title ? (ariaLabel || 'Details panel') : undefined}
        className={cn(
          'relative flex h-dvh w-full flex-col border-l border-border bg-surface-1 shadow-2xl focus:outline-none',
          width === 'lg' ? 'max-w-2xl' : 'max-w-lg',
        )}
      >
        <header
          className={cn(
            'flex shrink-0 border-b border-border',
            title || subtitle
              ? 'items-start justify-between gap-3 px-5 py-4'
              : 'items-center justify-end px-4 py-2.5',
          )}
        >
          {(title || subtitle) && (
            <div className="min-w-0">
              {title && <h3 id={titleID} className="text-sm font-semibold">{title}</h3>}
              {subtitle && <div className="mt-1 break-all text-xs text-text-muted">{subtitle}</div>}
            </div>
          )}
          <Button type="button" size="sm" variant="ghost" onClick={onClose} className="shrink-0">Close</Button>
        </header>
        <div ref={bodyRef} className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-5">
          {children}
        </div>
        {footer && (
          <footer className="shrink-0 border-t border-border p-4">
            {footer}
          </footer>
        )}
      </aside>
    </div>,
    document.body,
  )
}

export const Empty = ({ message }: { message: string }) => (
  <div className="flex items-center justify-center py-16"><p className="text-sm text-text-muted">{message}</p></div>
)

/* ── EmptyState ──────────────────────────────────────────────────────────
   Richer than <Empty>: icon + title + description + optional call-to-action.
   Use on pages where "there's nothing here yet" should nudge an action. */
export const EmptyState = ({ icon, title, description, action }: {
  icon?: React.ReactNode; title: string; description?: string; action?: React.ReactNode
}) => (
  <div className="flex flex-col items-center justify-center text-center py-16 px-6">
    {icon && <div className="grid place-items-center w-12 h-12 rounded-xl bg-surface-3 border border-border text-text-muted mb-4">{icon}</div>}
    <p className="text-sm font-semibold text-text-primary">{title}</p>
    {description && <p className="text-xs text-text-muted mt-1 max-w-sm">{description}</p>}
    {action && <div className="mt-4">{action}</div>}
  </div>
)

/* ── Skeleton ────────────────────────────────────────────────────────────
   Content-shaped loading placeholders. `.skeleton` (index.css) supplies the
   pulse + surface tint; here we only shape it. Respects reduced-motion via
   the global media query that neutralises animation-duration. */
export const Skeleton = ({ className, style }: { className?: string; style?: React.CSSProperties }) => (
  <div className={cn('skeleton', className || 'h-4 w-full')} style={style} />
)

// A block of stacked line-skeletons (e.g. a loading paragraph or list rows).
export const SkeletonText = ({ lines = 3, className }: { lines?: number; className?: string }) => (
  <div className={cn('space-y-2', className)}>
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} className="h-3.5 rounded" style={{ width: `${90 - (i % 3) * 18}%` }} />
    ))}
  </div>
)

// A table-shaped skeleton for list pages that stream large result sets.
export const SkeletonRows = ({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) => (
  <div className="space-y-2">
    {Array.from({ length: rows }).map((_, r) => (
      <div key={r} className="flex items-center gap-4 px-4 py-2.5">
        {Array.from({ length: cols }).map((_, c) => (
          <Skeleton key={c} className="h-3.5 rounded" style={{ flex: c === 0 ? '0 0 40%' : '1 1 0%' }} />
        ))}
      </div>
    ))}
  </div>
)

/* ── VirtualList ─────────────────────────────────────────────────────────
   Lightweight fixed-height windowed list — no external dependency. Renders
   only the rows in view (plus an overscan margin), so 5k–50k rows scroll at
   60fps instead of mounting tens of thousands of DOM nodes. Requires a fixed
   `rowHeight`; the scroll container gets `height`. For variable-height rows
   fall back to pagination. */
export function VirtualList<T>({ items, rowHeight, height, overscan = 8, renderRow, className, empty }: {
  items: T[]
  rowHeight: number
  height: number
  overscan?: number
  renderRow: (item: T, index: number) => React.ReactNode
  className?: string
  empty?: React.ReactNode
}) {
  const [scrollTop, setScrollTop] = React.useState(0)
  if (items.length === 0 && empty) return <>{empty}</>
  const total = items.length * rowHeight
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
  const visible = Math.ceil(height / rowHeight) + overscan * 2
  const last = Math.min(items.length, first + visible)
  const slice: React.ReactNode[] = []
  for (let i = first; i < last; i++) {
    slice.push(
      <div key={i} style={{ position: 'absolute', top: i * rowHeight, left: 0, right: 0, height: rowHeight }}>
        {renderRow(items[i], i)}
      </div>
    )
  }
  return (
    <div className={cn('overflow-y-auto no-scrollbar', className)} style={{ height }}
      onScroll={e => setScrollTop((e.target as HTMLDivElement).scrollTop)}>
      <div style={{ position: 'relative', height: total }}>{slice}</div>
    </div>
  )
}

export const CopyButton = ({ text }: { text: string }) => {
  const [copied, setCopied] = React.useState(false)
  return (
    <button onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })}
      className="text-text-muted hover:text-text-primary transition-colors text-xs" title="Copy">
      {copied ? '✓' : '⎘'}
    </button>
  )
}

export const StatCard = ({ label, value, color }: { label: string; value: string|number; color?: string }) => (
  <div className="card-hover p-4 relative overflow-hidden group">
    <span className="absolute inset-x-0 top-0 h-px opacity-60" style={{ backgroundImage: 'var(--grad-accent)' }} />
    <p className="text-xs text-text-muted mb-1 uppercase tracking-wider">{label}</p>
    <p className={cn('text-3xl font-bold tabular-nums tracking-tight', color || 'text-text-primary')}>{value}</p>
  </div>
)

export const Table = ({ headers, children, empty }: { headers: string[]; children?: React.ReactNode; empty?: boolean }) => (
  <div className="overflow-x-auto">
    <table className="w-full">
      <thead><tr className="border-b border-border">{headers.map(h => <th key={h} className="table-header">{h}</th>)}</tr></thead>
      <tbody>{empty ? <tr><td colSpan={headers.length}><Empty message="No data found"/></td></tr> : children}</tbody>
    </table>
  </div>
)

export { ErrorBoundary } from './ErrorBoundary'
