import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Modal, CopyButton } from '../ui'
import { APIError, findings as findingsApi } from '../../lib/api'
import { cn, truncate } from '../../lib/utils'
import type { FileBodyResponse } from '../../types'
import {
  beautifyCode,
  buildDiffBlocks,
  foldContextLines,
  shouldAutoBeautify,
  type DiffBlock,
  type DiffLine,
} from './diffModel'
import {
  buildSandboxedPreviewDoc,
  diffCSSVisual,
  type CSSSelectorDeclDiff,
  type SafeVisualTile,
} from './cssDiffModel'

type Props = {
  targetId: string
  url: string
  kind: 'css' | 'js'
  expectedOldHash?: string
  expectedNewHash?: string
  onClose: () => void
}

type ViewerTab = 'visual' | 'preview' | 'code'
type CodeViewMode = 'changes' | 'full'
type PreviewLayout = 'side-by-side' | 'stacked'
type PreviewTheme = 'light' | 'dark'

const CHECKERBOARD_STYLE: React.CSSProperties = {
  backgroundImage:
    'linear-gradient(45deg, #2a3449 25%, transparent 25%), linear-gradient(-45deg, #2a3449 25%, transparent 25%), linear-gradient(45deg, transparent 75%, #2a3449 75%), linear-gradient(-45deg, transparent 75%, #2a3449 75%)',
  backgroundSize: '8px 8px',
  backgroundPosition: '0 0, 0 4px, 4px -4px, -4px 0px',
  backgroundColor: '#171d2c',
}

function looksLikeHexHash(value?: string): boolean {
  if (!value) return false
  return /^[0-9a-f]{8,}$/i.test(value.trim())
}

function hashesMatch(expected: string, actual: string): boolean {
  const a = expected.trim().toLowerCase()
  const b = actual.trim().toLowerCase()
  if (!a || !b) return false
  return a === b || a.startsWith(b) || b.startsWith(a)
}

function isNotFoundError(err: unknown): boolean {
  if (err instanceof APIError && err.status === 404) return true
  if (err instanceof Error && /no capture|not found|\b404\b/i.test(err.message)) return true
  return false
}

function ColorSwatch({ color, label }: { color: string | null; label?: string }) {
  if (!color) {
    return (
      <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded border border-border-strong bg-surface-3 text-[9px] text-text-muted">
        —
      </span>
    )
  }
  return (
    <span
      className="relative inline-block h-5 w-5 shrink-0 overflow-hidden rounded border border-border-strong"
      style={CHECKERBOARD_STYLE}
      title={label || color}
    >
      <span className="absolute inset-0 block" style={{ backgroundColor: color }} />
    </span>
  )
}

function SafeTilePreview({ tile }: { tile: SafeVisualTile | null }) {
  if (!tile) return null
  switch (tile.kind) {
    case 'color':
      return <ColorSwatch color={tile.color} />
    case 'gradient':
      return (
        <span
          className="relative inline-block h-5 w-10 shrink-0 overflow-hidden rounded border border-border-strong"
          style={CHECKERBOARD_STYLE}
          title={tile.gradient}
        >
          <span className="absolute inset-0 block" style={{ backgroundImage: tile.gradient }} />
        </span>
      )
    case 'font-size':
      return (
        <span
          className="inline-flex items-center justify-center rounded border border-border bg-surface-3 px-1.5 leading-none text-text-primary shrink-0"
          style={{ fontSize: `${tile.px}px` }}
        >
          Aa
        </span>
      )
    case 'font-weight':
      return (
        <span
          className="inline-flex items-center justify-center rounded border border-border bg-surface-3 px-1.5 py-0.5 text-xs text-text-primary shrink-0"
          style={{ fontWeight: tile.weight }}
        >
          Aa
        </span>
      )
    case 'border-radius':
      return (
        <span
          className="inline-block h-5 w-5 shrink-0 border border-accent bg-accent/20"
          style={{ borderRadius: `${tile.px}px` }}
        />
      )
    case 'opacity':
      return (
        <span
          className="relative inline-block h-5 w-5 shrink-0 overflow-hidden rounded border border-border-strong"
          style={CHECKERBOARD_STYLE}
        >
          <span className="absolute inset-0 block bg-accent" style={{ opacity: tile.value }} />
        </span>
      )
    case 'border':
      return (
        <span
          className="inline-block h-5 w-7 shrink-0 rounded-sm bg-surface-3"
          style={{ border: `${tile.widthPx}px ${tile.style} ${tile.color}` }}
        />
      )
    case 'box-shadow':
      return (
        <span
          className="inline-block h-5 w-7 shrink-0 rounded-sm bg-surface-4 border border-border"
          style={{ boxShadow: tile.shadow }}
        />
      )
  }
}

function findMatchingChangeIndex(
  blocks: DiffBlock[],
  selector: string,
  property?: string,
  value?: string | null,
): { changeIndex: number; precedingContextIdx: number | null } {
  const selNeedle = selector.trim().toLowerCase()
  const propNeedle = property ? property.trim().toLowerCase() : ''
  const valNeedle = value ? value.trim().toLowerCase() : ''

  let bestScore = -1
  let bestChangeIdx = 0
  let bestPrecedingCtx: number | null = null

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i]
    if (block.kind !== 'change') continue

    const blockText = block.lines.map(l => l.text).join('\n').toLowerCase()
    const prevBlock = i > 0 ? blocks[i - 1] : null
    const prevContextText =
      prevBlock && prevBlock.kind === 'context'
        ? prevBlock.lines.map(l => l.text).join('\n').toLowerCase()
        : ''

    const hasProp = !!propNeedle && blockText.includes(propNeedle)
    const hasVal = !!valNeedle && blockText.includes(valNeedle)
    const hasSelInBlock = !!selNeedle && blockText.includes(selNeedle)
    const hasSelInPrev = !!selNeedle && prevContextText.includes(selNeedle)

    let score = 0
    if (hasProp && hasVal && (hasSelInBlock || hasSelInPrev)) score = 100
    else if (hasProp && (hasSelInBlock || hasSelInPrev)) score = 80
    else if (hasProp && hasVal) score = 60
    else if (hasSelInBlock) score = 50
    else if (hasProp) score = 30
    else if (hasVal) score = 20
    else if (hasSelInPrev) score = 10

    if (score > bestScore) {
      bestScore = score
      bestChangeIdx = block.changeIndex
      bestPrecedingCtx = hasSelInPrev && prevBlock?.kind === 'context' ? i - 1 : null
    }
  }

  return { changeIndex: bestChangeIdx, precedingContextIdx: bestPrecedingCtx }
}

function DiffLineRow({ line }: { line: DiffLine }) {
  return (
    <div
      className={cn(
        'flex items-start font-mono text-[11px] leading-[1.45] px-2',
        line.kind === 'added' && 'bg-severity-low/10 text-severity-low',
        line.kind === 'removed' && 'bg-severity-medium/10 text-severity-medium',
        line.kind === 'context' && 'text-text-muted',
      )}
    >
      <span className="w-10 shrink-0 select-none pr-2 text-right text-[10px] opacity-45 tabular-nums">
        {line.oldLine ?? ''}
      </span>
      <span className="w-10 shrink-0 select-none pr-2 text-right text-[10px] opacity-45 tabular-nums">
        {line.newLine ?? ''}
      </span>
      <span className="w-4 shrink-0 select-none opacity-70">
        {line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : ' '}
      </span>
      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all">{line.text}</span>
    </div>
  )
}

// Line-level + visual diff for a monitored stylesheet/script change (css_change /
// js_change rows). Both sides are read from the body captured at detection time
// (monitor.go's css_files/js_files) — never a live re-fetch: a live fetch would
// show today's bytes on both sides and pull a possibly third-party URL through
// a fresh GET on every modal open.
export function ChangeDiffViewer({
  targetId,
  url,
  kind,
  expectedOldHash,
  expectedNewHash,
  onClose,
}: Props) {
  const [current, setCurrent] = useState<FileBodyResponse | null>(null)
  const [previous, setPrevious] = useState<FileBodyResponse | null>(null)
  const [error, setError] = useState('')
  const [notFound, setNotFound] = useState(false)
  const [loading, setLoading] = useState(true)

  const [activeTab, setActiveTab] = useState<ViewerTab>('code')
  const [viewMode, setViewMode] = useState<CodeViewMode>('changes')
  const [beautify, setBeautify] = useState(false)
  const [activeIdx, setActiveIdx] = useState(0)
  const [expandedBlocks, setExpandedBlocks] = useState<Set<number>>(() => new Set())
  const [previewLayout, setPreviewLayout] = useState<PreviewLayout>('side-by-side')
  const [previewTheme, setPreviewTheme] = useState<PreviewTheme>('light')

  const hunkRefs = useRef<Record<number, HTMLDivElement | null>>({})
  const pendingScrollIdxRef = useRef<number | null>(null)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError('')
    setNotFound(false)
    setCurrent(null)
    setPrevious(null)
    setExpandedBlocks(new Set())
    setActiveIdx(0)
    Promise.all([
      findingsApi.fileBody(targetId, kind, url, 'current'),
      findingsApi.fileBody(targetId, kind, url, 'old'),
    ])
      .then(([cur, prev]) => {
        if (!alive) return
        setCurrent(cur)
        setPrevious(prev)
        setLoading(false)
      })
      .catch(e => {
        if (!alive) return
        if (isNotFoundError(e)) {
          setNotFound(true)
        } else {
          setError(e instanceof Error ? e.message : 'Failed to load stored file bodies')
        }
        setLoading(false)
      })
    return () => { alive = false }
  }, [targetId, kind, url])

  const bothCaptured = !!previous?.captured && !!current?.captured

  // Compute beautify eligibility & bounded beautified text.
  const beautifyInfo = useMemo(() => {
    if (!bothCaptured) {
      return {
        autoRecommended: false,
        exceededCap: false,
        oldBeautified: previous?.content || '',
        newBeautified: current?.content || '',
      }
    }
    const rawOld = previous?.content || ''
    const rawNew = current?.content || ''
    const autoRecommended = shouldAutoBeautify(rawOld, rawNew)
    const oldRes = beautifyCode(rawOld, kind)
    const newRes = beautifyCode(rawNew, kind)
    const exceededCap = oldRes.exceededCap || newRes.exceededCap
    return {
      autoRecommended,
      exceededCap,
      oldBeautified: oldRes.text,
      newBeautified: newRes.text,
    }
  }, [bothCaptured, previous?.content, current?.content, kind])

  // Visual CSS diff (computed only when kind === 'css' and both sides captured).
  const cssVisual = useMemo(() => {
    if (kind !== 'css' || !bothCaptured) return null
    return diffCSSVisual(previous?.content || '', current?.content || '')
  }, [kind, bothCaptured, previous?.content, current?.content])

  // Set default tab and auto-beautify whenever loaded snapshots change.
  useEffect(() => {
    if (loading || !bothCaptured) {
      setActiveTab('code')
      setBeautify(false)
      return
    }
    setBeautify(beautifyInfo.autoRecommended && !beautifyInfo.exceededCap)
    if (kind === 'css' && cssVisual?.hasVisualDiffs) {
      setActiveTab('visual')
    } else {
      setActiveTab('code')
    }
  }, [loading, bothCaptured, kind, url, beautifyInfo.autoRecommended, beautifyInfo.exceededCap, cssVisual?.hasVisualDiffs])

  // Effective text pair for Code diff.
  const diff = useMemo(() => {
    if (!bothCaptured) {
      return { blocks: [], totalChanges: 0, addedLines: 0, removedLines: 0, simplified: false }
    }
    const oldText = beautify && !beautifyInfo.exceededCap ? beautifyInfo.oldBeautified : (previous?.content || '')
    const newText = beautify && !beautifyInfo.exceededCap ? beautifyInfo.newBeautified : (current?.content || '')
    return buildDiffBlocks(oldText, newText)
  }, [bothCaptured, beautify, beautifyInfo.exceededCap, beautifyInfo.oldBeautified, beautifyInfo.newBeautified, previous?.content, current?.content])

  // Raw-byte truncation check (never derived from beautified line counts).
  const truncated =
    bothCaptured &&
    previous.content === current.content &&
    previous.hash !== current.hash

  // Formatting/whitespace-only diff hidden by Beautify.
  const whitespaceOnlyHidden =
    bothCaptured &&
    previous.content !== current.content &&
    diff.totalChanges === 0

  // Stale-snapshot check when an older historical change row's hashes no longer
  // match the single retained old_body/body pair.
  const staleSnapshot = useMemo(() => {
    if (loading || error || notFound || (!previous && !current)) return false
    const oldMismatch =
      looksLikeHexHash(expectedOldHash) &&
      !!previous?.hash &&
      !hashesMatch(expectedOldHash!, previous.hash)
    const newMismatch =
      looksLikeHexHash(expectedNewHash) &&
      !!current?.hash &&
      !hashesMatch(expectedNewHash!, current.hash)
    return oldMismatch || newMismatch
  }, [loading, error, notFound, expectedOldHash, expectedNewHash, previous, current])

  // Reset active hunk index whenever totalChanges, beautify, url, or kind changes.
  useEffect(() => {
    setActiveIdx(0)
    setExpandedBlocks(new Set())
  }, [diff.totalChanges, beautify, url, kind])

  // Perform pending scrollIntoView after tab switch or step change renders.
  useEffect(() => {
    if (activeTab !== 'code') return
    if (pendingScrollIdxRef.current !== null) {
      const idx = pendingScrollIdxRef.current
      pendingScrollIdxRef.current = null
      hunkRefs.current[idx]?.scrollIntoView?.({ block: 'center' })
    }
  }, [activeTab, activeIdx, diff])

  const stepChange = useCallback(
    (delta: number) => {
      if (diff.totalChanges <= 1) return
      setActiveIdx(prev => {
        const next = (prev + delta + diff.totalChanges) % diff.totalChanges
        pendingScrollIdxRef.current = next
        return next
      })
    },
    [diff.totalChanges],
  )

  // Keyboard shortcuts j/n (Next) and k/p (Prev) gated strictly on Code diff tab.
  useEffect(() => {
    if (activeTab !== 'code' || diff.totalChanges <= 1) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return
      const target = e.target as HTMLElement | null
      if (target && typeof target.closest === 'function' && target.closest('input, textarea, select, [contenteditable="true"]')) {
        return
      }
      if (e.key === 'j' || e.key === 'n') {
        e.preventDefault()
        stepChange(1)
      } else if (e.key === 'k' || e.key === 'p') {
        e.preventDefault()
        stepChange(-1)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [activeTab, diff.totalChanges, stepChange])

  const jumpToCode = useCallback(
    (selector: string, decl?: CSSSelectorDeclDiff) => {
      const targetVal = decl ? (decl.newRaw ?? decl.oldRaw) : null
      const { changeIndex, precedingContextIdx } = findMatchingChangeIndex(
        diff.blocks,
        selector,
        decl?.property,
        targetVal,
      )
      if (precedingContextIdx !== null) {
        setExpandedBlocks(prev => {
          const next = new Set(prev)
          next.add(precedingContextIdx)
          return next
        })
      }
      setActiveTab('code')
      setActiveIdx(changeIndex)
      pendingScrollIdxRef.current = changeIndex
    },
    [diff.blocks],
  )

  // Memoized hardened srcDoc payloads for Preview tab.
  const previewDocs = useMemo(() => {
    if (kind !== 'css' || !bothCaptured || activeTab !== 'preview') return null
    const selectors = cssVisual?.changedSelectors ?? []
    return {
      oldDoc: buildSandboxedPreviewDoc(previous?.content || '', selectors, previewTheme),
      newDoc: buildSandboxedPreviewDoc(current?.content || '', selectors, previewTheme),
    }
  }, [kind, bothCaptured, activeTab, cssVisual?.changedSelectors, previous?.content, current?.content, previewTheme])

  const showCSSTabs = kind === 'css' && bothCaptured && !loading && !error && !notFound

  const footer = (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <span className="text-xs text-text-muted tabular-nums">
        <span className="text-severity-low">+{diff.addedLines.toLocaleString()}</span>
        {' / '}
        <span className="text-severity-medium">−{diff.removedLines.toLocaleString()}</span>
        {' lines'}
      </span>
      {!loading && !error && !notFound && (
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] uppercase tracking-wider text-text-muted shrink-0">
              Old ({previous?.hash ? previous.hash.slice(0, 12) : '—'})
            </span>
            {previous?.captured ? (
              <CopyButton text={previous.content} />
            ) : (
              <span className="text-[10px] text-text-muted">not captured</span>
            )}
          </div>
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] uppercase tracking-wider text-text-muted shrink-0">
              Current ({current?.hash ? current.hash.slice(0, 12) : '—'})
            </span>
            {current?.captured ? (
              <CopyButton text={current.content} />
            ) : (
              <span className="text-[10px] text-text-muted">not captured</span>
            )}
          </div>
        </div>
      )}
    </div>
  )

  return (
    <Modal
      open
      onClose={onClose}
      width="2xl"
      title={`${kind === 'css' ? 'Stylesheet' : 'JavaScript'} diff — ${truncate(url, 80)}`}
      bodyClassName="flex flex-col !overflow-hidden !p-0"
      footer={footer}
    >
      {/* Non-scrolling top header / banners / tabs / toolbar */}
      <div className="shrink-0 border-b border-border bg-surface-2">
        <div className="px-4 sm:px-5 pt-3 pb-2">
          <p className="font-mono text-[11px] text-text-muted break-all">{url}</p>
        </div>

        {staleSnapshot && (
          <div
            role="status"
            className="mx-4 sm:mx-5 mb-2 rounded-md border border-accent/30 bg-accent/10 px-3 py-1.5 text-[11px] text-text-secondary"
          >
            Only the latest snapshot pair is retained for this asset — the stored hashes do not match this historical change row, so you are viewing the most recent revision diff.
          </div>
        )}

        {!loading && !error && !notFound && !bothCaptured && (
          <div className="mx-4 sm:mx-5 mb-2 rounded-md border border-border bg-surface-3 px-3 py-1.5 text-[11px] text-text-muted">
            {!previous?.captured && !current?.captured
              ? 'Neither side was captured — this row predates content tracking. Recorded hashes only.'
              : !previous?.captured
              ? 'Original content was not captured — this row predates content tracking. Current capture shown read-only.'
              : 'Current content was not captured. Stored original shown read-only.'}
          </div>
        )}

        {!loading && !error && !notFound && truncated && (
          <div
            role="status"
            className="mx-4 sm:mx-5 mb-2 rounded-md border border-severity-medium/30 bg-severity-medium/10 px-3 py-1.5 text-[11px] text-severity-medium"
          >
            Both snapshots hold identical bytes but the recorded hashes differ — the change sits past the 256 KB capture cap.
          </div>
        )}

        {showCSSTabs && (
          <div className="flex items-center gap-1 px-4 sm:px-5 pt-1 border-t border-border/60" role="tablist" aria-label="Stylesheet diff view">
            {([
              { id: 'visual', label: 'Visual' },
              { id: 'preview', label: 'Preview' },
              { id: 'code', label: 'Code diff' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-accent text-text-primary'
                    : 'border-transparent text-text-muted hover:text-text-secondary',
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}

        {/* Code diff toolbar */}
        {!loading && !error && !notFound && bothCaptured && activeTab === 'code' && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 sm:px-5 py-2 border-t border-border/60 bg-surface-1/60">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex rounded-md border border-border bg-surface-2 p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setViewMode('changes')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    viewMode === 'changes'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Changes only
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('full')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    viewMode === 'full'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Full file
                </button>
              </div>

              <button
                type="button"
                aria-pressed={beautify && !beautifyInfo.exceededCap}
                disabled={beautifyInfo.exceededCap}
                title={
                  beautifyInfo.exceededCap
                    ? 'Beautified output exceeds the 12,000-line safety cap'
                    : 'Format minified code before diffing'
                }
                onClick={() => setBeautify(b => !b)}
                className={cn(
                  'rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors',
                  beautifyInfo.exceededCap
                    ? 'border-border bg-surface-2 text-text-muted opacity-50 cursor-not-allowed'
                    : beautify
                    ? 'border-accent/50 bg-accent/15 text-text-primary'
                    : 'border-border bg-surface-2 text-text-muted hover:text-text-secondary',
                )}
              >
                Beautify
              </button>
            </div>

            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-text-muted tabular-nums" data-testid="change-counter">
                {diff.totalChanges > 0
                  ? `Change ${activeIdx + 1} / ${diff.totalChanges}`
                  : '0 changes'}
              </span>
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  disabled={diff.totalChanges <= 1}
                  onClick={() => stepChange(-1)}
                  className={cn(
                    'rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium transition-colors',
                    diff.totalChanges <= 1
                      ? 'text-text-muted opacity-40 cursor-not-allowed'
                      : 'text-text-primary hover:bg-surface-3',
                  )}
                >
                  ◀ Prev
                </button>
                <button
                  type="button"
                  disabled={diff.totalChanges <= 1}
                  onClick={() => stepChange(1)}
                  className={cn(
                    'rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium transition-colors',
                    diff.totalChanges <= 1
                      ? 'text-text-muted opacity-40 cursor-not-allowed'
                      : 'text-text-primary hover:bg-surface-3',
                  )}
                >
                  Next ▶
                </button>
              </div>
              <span className="hidden sm:inline text-text-muted tabular-nums pl-1 border-l border-border">
                <span className="text-severity-low">+{diff.addedLines.toLocaleString()}</span>
                {' / '}
                <span className="text-severity-medium">−{diff.removedLines.toLocaleString()}</span>
              </span>
            </div>
          </div>
        )}

        {/* Preview toolbar */}
        {showCSSTabs && activeTab === 'preview' && (
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 sm:px-5 py-2 border-t border-border/60 bg-surface-1/60">
            <div className="flex items-center gap-2">
              <div className="inline-flex rounded-md border border-border bg-surface-2 p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setPreviewLayout('side-by-side')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    previewLayout === 'side-by-side'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Side-by-side
                </button>
                <button
                  type="button"
                  onClick={() => setPreviewLayout('stacked')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    previewLayout === 'stacked'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Stacked
                </button>
              </div>

              <div className="inline-flex rounded-md border border-border bg-surface-2 p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setPreviewTheme('light')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    previewTheme === 'light'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Light
                </button>
                <button
                  type="button"
                  onClick={() => setPreviewTheme('dark')}
                  className={cn(
                    'rounded px-2 py-0.5 font-medium transition-colors',
                    previewTheme === 'dark'
                      ? 'bg-accent/20 text-text-primary'
                      : 'text-text-muted hover:text-text-secondary',
                  )}
                >
                  Dark
                </button>
              </div>
            </div>
            <span className="text-[11px] text-text-muted">
              Sandboxed offline specimen — external resources and scripts blocked
            </span>
          </div>
        )}
      </div>

      {/* Single scrollable content area */}
      <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain">
        {loading && (
          <p className="text-xs text-text-muted py-12 text-center">Loading stored snapshots…</p>
        )}

        {!loading && notFound && (
          <div className="py-12 px-6 text-center">
            <p className="text-sm font-medium text-text-primary mb-1">
              No snapshot body captured yet
            </p>
            <p className="text-xs text-text-muted max-w-md mx-auto">
              This asset does not have a stored response body on disk yet (older or hash-only monitor entry). Future monitor rounds that capture body content will appear here.
            </p>
          </div>
        )}

        {!loading && !notFound && error && (
          <p className="text-xs text-severity-medium py-12 text-center px-4">{error}</p>
        )}

        {/* Visual CSS tab */}
        {!loading && !error && !notFound && showCSSTabs && activeTab === 'visual' && cssVisual && (
          <div className="p-4 sm:p-5 space-y-5">
            {cssVisual.colorChanges.length > 0 && (
              <section>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                  Color changes ({cssVisual.colorChanges.length})
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                  {cssVisual.colorChanges.map(item => (
                    <div
                      key={item.id}
                      className="rounded-lg border border-border bg-surface-1 p-2.5 flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="font-mono text-[11px] text-text-primary truncate" title={item.selector}>
                          {item.selector}
                        </div>
                        <div className="font-mono text-[10px] text-text-muted truncate">
                          {item.property}
                        </div>
                        <div className="font-mono text-[10px] text-text-secondary truncate mt-0.5">
                          {item.oldRaw ?? '∅'} → {item.newRaw ?? '∅'}
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <ColorSwatch color={item.oldColor} label={`Old: ${item.oldColor ?? 'none'}`} />
                        <span className="text-[10px] text-text-muted">→</span>
                        <ColorSwatch color={item.newColor} label={`New: ${item.newColor ?? 'none'}`} />
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {cssVisual.tokenChanges.length > 0 && (
              <section>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                  Custom properties ({cssVisual.tokenChanges.length})
                </h3>
                <div className="rounded-lg border border-border bg-surface-1 divide-y divide-border">
                  {cssVisual.tokenChanges.map((tok, idx) => (
                    <div
                      key={`${tok.selector}:${tok.name}:${idx}`}
                      className="px-3 py-2 flex flex-wrap items-center justify-between gap-2 text-[11px]"
                    >
                      <div className="min-w-0">
                        <span className="font-mono font-medium text-accent">{tok.name}</span>
                        <span className="ml-2 font-mono text-[10px] text-text-muted">{tok.selector}</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono text-[11px]">
                        {tok.oldColor && <ColorSwatch color={tok.oldColor} />}
                        <span className="text-severity-medium line-through opacity-80">{tok.oldRaw ?? '∅'}</span>
                        <span className="text-text-muted">→</span>
                        {tok.newColor && <ColorSwatch color={tok.newColor} />}
                        <span className="text-severity-low">{tok.newRaw ?? '∅'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {cssVisual.selectorDiffs.length > 0 ? (
              <section>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                  Selector changes ({cssVisual.selectorDiffs.length})
                </h3>
                <div className="space-y-3">
                  {cssVisual.selectorDiffs.map((card, idx) => (
                    <div
                      key={`${card.atRule}|${card.selector}|${idx}`}
                      className="rounded-lg border border-border bg-surface-1 overflow-hidden"
                    >
                      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-border bg-surface-2/60">
                        <div className="flex flex-wrap items-center gap-2 min-w-0">
                          {card.atRule && (
                            <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-accent">
                              {card.atRule}
                            </span>
                          )}
                          <span className="font-mono text-xs font-medium text-text-primary break-all">
                            {card.selector}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => jumpToCode(card.selector, card.declarations[0])}
                          className="shrink-0 rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-text-secondary hover:text-text-primary hover:bg-surface-3 transition-colors"
                        >
                          Jump to code
                        </button>
                      </div>
                      <div className="divide-y divide-border/50">
                        {card.declarations.map(decl => (
                          <div
                            key={decl.property}
                            className="px-3 py-2 flex flex-wrap items-center justify-between gap-3 text-[11px]"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span
                                className={cn(
                                  'inline-block w-1.5 h-1.5 rounded-full shrink-0',
                                  decl.status === 'added'
                                    ? 'bg-severity-low'
                                    : decl.status === 'removed'
                                    ? 'bg-severity-medium'
                                    : 'bg-accent',
                                )}
                              />
                              <span className="font-mono text-text-primary">{decl.property}</span>
                            </div>
                            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                              {decl.oldRaw !== null && (
                                <span className="inline-flex items-center gap-1.5 text-severity-medium">
                                  <SafeTilePreview tile={decl.oldTile} />
                                  <span className="break-all">{decl.oldRaw}</span>
                                </span>
                              )}
                              {decl.oldRaw !== null && decl.newRaw !== null && (
                                <span className="text-text-muted">→</span>
                              )}
                              {decl.newRaw !== null && (
                                <span className="inline-flex items-center gap-1.5 text-severity-low">
                                  <SafeTilePreview tile={decl.newTile} />
                                  <span className="break-all">{decl.newRaw}</span>
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            ) : (
              <p className="text-xs text-text-muted py-8 text-center">
                No structured CSS rule changes detected. Switch to Code diff to inspect raw lines.
              </p>
            )}
          </div>
        )}

        {/* Sandboxed Preview tab */}
        {!loading && !error && !notFound && showCSSTabs && activeTab === 'preview' && previewDocs && (
          <div
            className={cn(
              'p-4 gap-3 grid',
              previewLayout === 'side-by-side' ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1',
            )}
          >
            <div className="rounded-lg border border-border overflow-hidden bg-surface-1 flex flex-col">
              <div className="px-3 py-1.5 border-b border-border bg-surface-2 text-[11px] font-medium text-text-secondary">
                Before (Old)
              </div>
              <iframe
                title="Stylesheet preview — Before"
                sandbox=""
                referrerPolicy="no-referrer"
                tabIndex={-1}
                className="w-full min-h-[420px] pointer-events-none border-0"
                srcDoc={previewDocs.oldDoc}
              />
            </div>
            <div className="rounded-lg border border-border overflow-hidden bg-surface-1 flex flex-col">
              <div className="px-3 py-1.5 border-b border-border bg-surface-2 text-[11px] font-medium text-text-secondary">
                After (Current)
              </div>
              <iframe
                title="Stylesheet preview — After"
                sandbox=""
                referrerPolicy="no-referrer"
                tabIndex={-1}
                className="w-full min-h-[420px] pointer-events-none border-0"
                srcDoc={previewDocs.newDoc}
              />
            </div>
          </div>
        )}

        {/* Code diff tab */}
        {!loading && !error && !notFound && activeTab === 'code' && (
          <div className="py-2">
            {bothCaptured ? (
              <>
                {whitespaceOnlyHidden && (
                  <div
                    role="status"
                    className="mx-4 sm:mx-5 mb-2 flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-surface-3 px-3 py-2 text-[11px] text-text-secondary"
                  >
                    <span>
                      Formatting/whitespace-only difference (hidden by Beautify) — switch to Raw to inspect.
                    </span>
                    {beautify && (
                      <button
                        type="button"
                        onClick={() => setBeautify(false)}
                        className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-text-primary hover:bg-surface-4"
                      >
                        Switch to Raw
                      </button>
                    )}
                  </div>
                )}

                {diff.simplified && (
                  <div
                    role="status"
                    className="mx-4 sm:mx-5 mb-2 rounded-md border border-severity-medium/30 bg-severity-medium/10 px-3 py-1.5 text-[11px] text-severity-medium"
                  >
                    Diff too large to align line-by-line — showing simplified diff.
                  </div>
                )}

                {diff.blocks.length === 0 ? (
                  <p className="px-4 py-8 text-center text-xs text-text-muted">
                    No stored content on either side.
                  </p>
                ) : (
                  <div>
                    {diff.blocks.map((block, blockIdx) => {
                      if (block.kind === 'context') {
                        const folded =
                          viewMode === 'changes' && !expandedBlocks.has(blockIdx)
                            ? foldContextLines(block.lines, 3)
                            : { collapsed: false, top: block.lines, hidden: [], bottom: [] }

                        return (
                          <div key={`ctx-${blockIdx}`}>
                            {folded.top.map((line, i) => (
                              <DiffLineRow key={`t-${i}`} line={line} />
                            ))}
                            {folded.collapsed && (
                              <button
                                type="button"
                                onClick={() =>
                                  setExpandedBlocks(prev => {
                                    const next = new Set(prev)
                                    next.add(blockIdx)
                                    return next
                                  })
                                }
                                className="w-full py-1 px-4 text-center font-mono text-[11px] text-accent bg-surface-3/60 hover:bg-surface-3 border-y border-border/50 transition-colors"
                              >
                                ··· {folded.hidden.length} unchanged lines (expand) ···
                              </button>
                            )}
                            {folded.bottom.map((line, i) => (
                              <DiffLineRow key={`b-${i}`} line={line} />
                            ))}
                          </div>
                        )
                      }

                      const isActive = block.changeIndex === activeIdx
                      return (
                        <div
                          key={`chg-${block.changeIndex}`}
                          ref={el => { hunkRefs.current[block.changeIndex] = el }}
                          data-change-index={block.changeIndex}
                          data-active-change={isActive ? 'true' : undefined}
                          onClick={() => setActiveIdx(block.changeIndex)}
                          className={cn(
                            'border-l-2 transition-colors',
                            isActive
                              ? 'border-accent bg-accent/[0.06]'
                              : 'border-transparent',
                          )}
                        >
                          {block.lines.map((line, i) => (
                            <DiffLineRow key={`l-${i}`} line={line} />
                          ))}
                        </div>
                      )
                    })}
                  </div>
                )}
              </>
            ) : (
              <div className="px-2">
                {((current?.captured ? current.content : previous?.content) || 'Not captured.')
                  .split('\n')
                  .map((line, j) => (
                    <div
                      key={j}
                      className="flex items-start px-2 py-px font-mono text-[11px] text-text-muted"
                    >
                      <span className="w-10 shrink-0 select-none pr-2 text-right text-[10px] opacity-45 tabular-nums">
                        {j + 1}
                      </span>
                      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all">{line}</span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}
