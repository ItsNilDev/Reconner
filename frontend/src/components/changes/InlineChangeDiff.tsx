import { cn } from '../../lib/utils'
import { statusCodeColor } from '../../lib/utils'
import { inlineDiffPieces, parseFormattedStatusTitle, parseStatusTransition } from './changesModel'

interface Props {
  oldValue: string
  newValue: string
  changeType: string
  oldStatus?: number
  newStatus?: number
}

function StatusPill({ code }: { code?: number }) {
  if (!code) return <span className="text-text-muted">—</span>
  return (
    <span className={cn('rounded border border-border px-1.5 py-0.5 font-mono text-xs tabular-nums', statusCodeColor(code))}>
      {code}
    </span>
  )
}

function InlineTextDiff({ oldText, newText, title }: { oldText: string; newText: string; title?: string }) {
  const pieces = inlineDiffPieces(oldText, newText)
  return (
    <span
      className="font-mono text-xs break-all whitespace-pre-wrap"
      title={title}
    >
      {pieces.map((piece, i) => (
        <span
          key={i}
          className={cn(
            piece.kind === 'removed' && 'bg-severity-medium/10 text-severity-medium line-through',
            piece.kind === 'added' && 'bg-severity-low/10 text-severity-low',
            piece.kind === 'same' && 'text-text-muted',
          )}
        >
          {piece.kind === 'removed' ? '−' : piece.kind === 'added' ? '+' : ''}{piece.text}
        </span>
      ))}
    </span>
  )
}

export default function InlineChangeDiff({ oldValue, newValue, changeType, oldStatus, newStatus }: Props) {
  const parsed = parseStatusTransition(oldValue, newValue)
  const fmtOld = parseFormattedStatusTitle(oldValue)
  const fmtNew = parseFormattedStatusTitle(newValue)
  const oldCode = oldStatus || parsed.oldCode
  const newCode = newStatus || parsed.newCode
  const statusTypes = ['status_change', 'http_change', 'page_change']

  if (statusTypes.includes(changeType)) {
    const hasFormattedPair = Boolean(fmtOld && fmtNew)
    const titleChanged = hasFormattedPair && fmtOld!.title !== fmtNew!.title
    const statusChanged = Boolean((oldCode || newCode) && oldCode !== newCode)

    if (!statusChanged && hasFormattedPair && titleChanged) {
      const stableCode = newCode || oldCode
      return (
        <span className="inline-flex flex-wrap items-center gap-1.5" title={`${oldValue} → ${newValue}`}>
          {stableCode && (
            <span className="opacity-70">
              <StatusPill code={stableCode} />
            </span>
          )}
          <InlineTextDiff oldText={fmtOld!.title || '(empty)'} newText={fmtNew!.title || '(empty)'} />
        </span>
      )
    }

    if (statusChanged && hasFormattedPair && titleChanged) {
      return (
        <span className="inline-flex flex-wrap items-center gap-1.5" title={`${oldValue} → ${newValue}`}>
          <StatusPill code={oldCode} />
          <span className="text-text-muted">→</span>
          <StatusPill code={newCode} />
          <InlineTextDiff oldText={fmtOld!.title || '(empty)'} newText={fmtNew!.title || '(empty)'} />
        </span>
      )
    }

    if (statusChanged) {
      return (
        <span className="inline-flex items-center gap-1.5" title={`${oldValue} → ${newValue}`}>
          <StatusPill code={oldCode} />
          <span className="text-text-muted">→</span>
          <StatusPill code={newCode} />
        </span>
      )
    }
  }

  return (
    <InlineTextDiff
      oldText={oldValue}
      newText={newValue}
      title={`Old: ${oldValue}\nNew: ${newValue}`}
    />
  )
}
