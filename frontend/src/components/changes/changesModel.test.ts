import { describe, expect, it } from 'vitest'
import {
  categoryForChangeType,
  changeBadgeVariant,
  changeHosts,
  inlineDiffPieces,
  isScopeEvent,
  parseStatusTransition,
  scopeEventSummary,
} from './changesModel'

describe('categoryForChangeType', () => {
  it('maps the new watch change types', () => {
    expect(categoryForChangeType('status_change')).toBe('http')
    expect(categoryForChangeType('page_change')).toBe('http')
    expect(categoryForChangeType('new_subdomain')).toBe('assets')
    expect(categoryForChangeType('scope_landed')).toBe('assets')
    expect(categoryForChangeType('scope_modified')).toBe('assets')
    expect(categoryForChangeType('scope_removed')).toBe('assets')
  })

  it('maps alert change types to the alerts category', () => {
    for (const type of [
      'watch_failed', 'watch_kind_conflict', 'monitor_failed',
      'monitor_escalation_started', 'scan_auto_paused', 'bounty_scope_change',
    ]) {
      expect(categoryForChangeType(type)).toBe('alerts')
    }
    expect(categoryForChangeType('new_host')).toBe('assets')
    expect(categoryForChangeType('scope_proposed')).toBe('assets')
    expect(categoryForChangeType('scope_rejected')).toBe('assets')
  })

  it('maps redirect_change and content_change to http', () => {
    expect(categoryForChangeType('redirect_change')).toBe('http')
    expect(categoryForChangeType('content_change')).toBe('http')
  })

  it('routes stylesheets and scripts to scripts, not css', () => {
    expect(categoryForChangeType('css_change')).toBe('scripts')
    expect(categoryForChangeType('js_change')).toBe('scripts')
    expect(categoryForChangeType('security:script_added')).toBe('scripts')
    expect(categoryForChangeType('security:stylesheet_added')).toBe('scripts')
  })

  it('routes header changes to headers before the security prefix', () => {
    expect(categoryForChangeType('security_header_removed')).toBe('headers')
    expect(categoryForChangeType('security:header_removed')).toBe('headers')
  })

  it('falls back to http for unknown or missing types', () => {
    expect(categoryForChangeType('')).toBe('http')
    expect(categoryForChangeType('something_new')).toBe('http')
  })
})

describe('changeBadgeVariant', () => {
  it('honours a stored severity including critical', () => {
    expect(changeBadgeVariant({ severity: 'critical' })).toBe('critical')
    expect(changeBadgeVariant({ severity: 'high' })).toBe('high')
    expect(changeBadgeVariant({ severity: 'info' })).toBe('info')
  })

  it('falls back by type when severity is missing', () => {
    expect(changeBadgeVariant({ change_type: 'js_change' })).toBe('medium')
    expect(changeBadgeVariant({ change_type: 'security:script_added' })).toBe('high')
    expect(changeBadgeVariant({ change_type: 'tech_change' })).toBe('low')
    expect(changeBadgeVariant({ change_type: 'status_change' })).toBe('info')
  })

  it('tolerates foreign rows without change_type or severity', () => {
    const stale = { id: 's1', target_id: 't1', subdomain: 'a.example.test' } as Record<string, unknown>
    expect(changeBadgeVariant(stale)).toBe('info')
  })
})

describe('changeHosts', () => {
  it('returns host names for a new_subdomain entry with metadata', () => {
    expect(changeHosts({
      change_type: 'new_subdomain',
      metadata: { hosts: ['a.example', 'b.example'], total: 2 },
    })).toEqual(['a.example', 'b.example'])
  })

  it('keeps only string host names', () => {
    expect(changeHosts({
      change_type: 'new_subdomain',
      metadata: { hosts: ['a.example', 42, null, 'b.example'] },
    })).toEqual(['a.example', 'b.example'])
  })

  it('returns null for other change types', () => {
    expect(changeHosts({ change_type: 'status_change', metadata: { hosts: ['a.example'] } })).toBeNull()
  })

  it('returns null for missing or malformed metadata', () => {
    expect(changeHosts({ change_type: 'new_subdomain' })).toBeNull()
    expect(changeHosts({ change_type: 'new_subdomain', metadata: { hosts: 'a.example' } })).toBeNull()
    expect(changeHosts({ change_type: 'new_subdomain', metadata: { hosts: [] } })).toBeNull()
  })
})

describe('parseStatusTransition', () => {
  it('reads codes from the monitor value format', () => {
    expect(parseStatusTransition('status=403 title=Forbidden', 'status=200 title=OK')).toEqual({ oldCode: 403, newCode: 200 })
  })

  it('ignores bare codes that do not match the monitor format', () => {
    // The server parses only "status=NNN " with a trailing space. Bare numbers
    // must not produce pills where status filters exclude the row.
    expect(parseStatusTransition('301', '302')).toEqual({ oldCode: undefined, newCode: undefined })
    expect(parseStatusTransition('status=200x', 'path /403')).toEqual({ oldCode: undefined, newCode: undefined })
  })

  it('reads the explicit status code after a timestamp', () => {
    expect(parseStatusTransition('2026-01-02 status=403 ', '2026-01-02 status=200 ')).toEqual({ oldCode: 403, newCode: 200 })
  })

  it('returns undefined when no code is present', () => {
    expect(parseStatusTransition('title changed', 'new title')).toEqual({ oldCode: undefined, newCode: undefined })
  })
})

describe('inlineDiffPieces', () => {
  it('marks only the changed words', () => {
    const pieces = inlineDiffPieces('Server: nginx', 'Server: apache')
    const removed = pieces.filter(p => p.kind === 'removed').map(p => p.text).join('')
    const added = pieces.filter(p => p.kind === 'added').map(p => p.text).join('')
    expect(removed).toContain('nginx')
    expect(added).toContain('apache')
    expect(pieces.some(p => p.kind === 'same' && p.text.includes('Server'))).toBe(true)
  })
})

describe('scope event recognition', () => {
  it('recognizes re-eligible and out-of-scope watch events', () => {
    expect(isScopeEvent({ change_type: 'scope_re_eligible' })).toBe(true)
    expect(isScopeEvent({ change_type: 'out_of_scope' })).toBe(true)
  })
})

describe('scopeEventSummary', () => {
  it('uses review-state aware scope verbs', () => {
    const base = { change_type: 'scope_landed', url: 'api.example.test' }
    expect(scopeEventSummary({ ...base, source: 'bounty', scope_status: 'pending', program_id: 'p1' })).toContain('Scope proposed.')
    expect(scopeEventSummary({ ...base, source: 'bounty', scope_status: 'superseded', program_id: 'p1' })).toContain('Proposal superseded.')
    expect(scopeEventSummary({ ...base, source: 'watch_scope', program_id: 'p1' })).toContain('Host landed.')
    expect(scopeEventSummary({ change_type: 'out_of_scope', url: 'api.example.test' })).toContain('Removed from eligible scope.')
  })
})
