import { describe, expect, it } from 'vitest'
import {
  categoryForChangeType,
  changeBadgeVariant,
  changeHosts,
  groupMonitorChanges,
  inlineDiffPieces,
  isDefaultFeedRow,
  monitorRowKind,
  NOTIFICATION_ALLOWED_TYPES,
  parseStatusTransition,
} from './changesModel'
import type { MonitoringChange } from '../../types'

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
    for (const type of NOTIFICATION_ALLOWED_TYPES) {
      if (type === 'new_host') continue
      expect(categoryForChangeType(type)).toBe('alerts')
    }
    expect(categoryForChangeType('new_host')).toBe('assets')
    expect(categoryForChangeType('scope_proposed')).toBe('assets')
    expect(categoryForChangeType('scope_rejected')).toBe('assets')
  })

  it('maps redirect_change to http', () => {
    expect(categoryForChangeType('redirect_change')).toBe('http')
  })

  it('routes stylesheets and scripts to scripts, not css', () => {
    expect(categoryForChangeType('css_change')).toBe('scripts')
    expect(categoryForChangeType('js_change')).toBe('scripts')
    expect(categoryForChangeType('security:script_added')).toBe('scripts')
    expect(categoryForChangeType('security:stylesheet_added')).toBe('scripts')
    expect(monitorRowKind({ change_type: 'css_change' })).toBe('scripts')
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

describe('isDefaultFeedRow', () => {
  it('keeps watch host discoveries and bounty scope rows', () => {
    expect(isDefaultFeedRow({ source: 'watch', change_type: 'new_subdomain' })).toBe(true)
    for (const type of ['scope_landed', 'scope_modified', 'scope_removed']) {
      expect(isDefaultFeedRow({ source: 'bounty', change_type: type })).toBe(true)
    }
  })

  it('keeps only allow-listed alert notifications', () => {
    for (const type of NOTIFICATION_ALLOWED_TYPES) {
      expect(isDefaultFeedRow({ source: 'notification', change_type: type })).toBe(true)
    }
    expect(isDefaultFeedRow({ source: 'notification', change_type: 'finding' })).toBe(false)
    expect(isDefaultFeedRow({ source: 'notification', change_type: 'scan_deep' })).toBe(false)
  })

  it('drops routine monitor and watch noise', () => {
    // An actual status transition is a daily signal and stays visible.
    expect(isDefaultFeedRow({ source: 'monitor', change_type: 'status_change' })).toBe(true)
    expect(isDefaultFeedRow({ source: 'monitor', change_type: 'http_change' })).toBe(true)
    expect(isDefaultFeedRow({ source: 'monitor', change_type: 'tech_change' })).toBe(false)
    expect(isDefaultFeedRow({ source: 'watch', change_type: 'status_change' })).toBe(false)
    expect(isDefaultFeedRow({ source: 'watch', change_type: 'new_subdomain_extra' })).toBe(false)
    expect(isDefaultFeedRow({ change_type: 'new_subdomain' })).toBe(false)
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

describe('groupMonitorChanges', () => {
  const row = (over: Partial<MonitoringChange>): MonitoringChange => ({
    id: over.id || 'x',
    target_id: over.target_id || '',
    url: over.url || '',
    change_type: over.change_type || '',
    old_value: over.old_value || '',
    new_value: over.new_value || '',
    severity: over.severity || 'info',
    detected_at: over.detected_at || '2026-01-01 00:00:00',
  })

  it('keeps the legacy three-part key for an empty identity', () => {
    const rows = [
      row({ id: '1', change_type: 'status_change', old_value: '403', new_value: '200' }),
      row({ id: '2', change_type: 'status_change', old_value: '403', new_value: '200', url: 'https://b.test' }),
    ]
    const groups = groupMonitorChanges(rows)
    expect(groups).toHaveLength(1)
    expect(groups[0].items).toHaveLength(2)
    expect(groups[0].urls).toEqual(['', 'https://b.test'])
  })

  it('separates identical changes from different targets when identity is supplied', () => {
    const rows = [
      row({ id: '1', target_id: 'a', change_type: 'status_change', old_value: '403', new_value: '200' }),
      row({ id: '2', target_id: 'b', change_type: 'status_change', old_value: '403', new_value: '200' }),
    ]
    const groups = groupMonitorChanges(rows, (r: MonitoringChange) => r.target_id)
    expect(groups).toHaveLength(2)
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
