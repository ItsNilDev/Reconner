import type { ChangeEntry } from '../../types'
import { Badge } from '../ui'
import {
  changeBadgeVariant, isScopeEvent, scopeChangedFields, scopeEventSummary, scopeReviewLabel,
} from './changesModel'

interface Props {
  item: ChangeEntry
  variant?: 'card' | 'details'
  programName?: string
}

// ScopeEventView is the single renderer for scope events. The feed keeps the
// original JSON snapshots for compatibility, but this component shows only the
// formatted summary, the changed fields, and the review status. It also covers
// legacy scope_landed rows whose snapshots may be missing or malformed.
export default function ScopeEventView({ item, variant = 'card', programName }: Props) {
  if (!isScopeEvent(item)) return null

  const summary = scopeEventSummary(item, programName)
  const fields = scopeChangedFields(item.old_value, item.new_value)
  const status = scopeReviewLabel(item.scope_status)
  const isDetails = variant === 'details'

  return (
    <div className={isDetails ? 'rounded-lg border border-white/[.06] bg-white/[.02] p-3' : 'min-w-0'}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
        {!isDetails && (
          <span className="w-32 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-text-muted">
            Scope
          </span>
        )}
        <span className="min-w-0 break-words text-text-primary" title={summary}>{summary}</span>
        {status && (
          <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-text-muted">
            {status}
          </span>
        )}
        {!isDetails && <Badge variant={changeBadgeVariant(item)}>{item.severity}</Badge>}
      </div>
      {fields.length > 0 && (
        <div className={isDetails ? 'mt-2 space-y-1 text-xs' : 'mt-1 space-y-0.5 pl-32 text-[11px] text-text-muted'}>
          {fields.map(field => (
            <div key={field.field} className="flex flex-wrap items-baseline gap-x-1.5">
              <span className="font-semibold text-text-muted">{field.field}:</span>
              <span className="text-severity-medium line-through">{field.before}</span>
              <span className="text-text-muted">→</span>
              <span className="text-severity-low">{field.after}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
