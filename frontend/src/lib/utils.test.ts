import { afterEach, describe, expect, it, vi } from 'vitest'
import { safeHref, timeUntil } from './utils'

describe('timeUntil', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders a future schedule as a wait', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-11-17T12:00:00Z'))
    expect(timeUntil('2026-11-17T12:37:00Z')).toBe('in 37m')
  })

  it('renders a past schedule as overdue', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-11-17T12:00:00Z'))
    expect(timeUntil('2026-11-17T11:23:00Z')).toBe('37m overdue')
  })

  it('handles a missing schedule', () => {
    expect(timeUntil(null)).toBe('not scheduled')
  })
})

describe('safeHref', () => {
  it('keeps http and https links', () => {
    expect(safeHref('https://a.example.test/path')).toBe('https://a.example.test/path')
    expect(safeHref('http://a.example.test')).toBe('http://a.example.test')
  })

  it('promotes bare hosts to https', () => {
    expect(safeHref('a.example.test')).toBe('https://a.example.test')
    expect(safeHref('a.example.test:8443/x?y=1')).toBe('https://a.example.test:8443/x?y=1')
    expect(safeHref('//a.example.test')).toBe('https://a.example.test')
  })

  it('rejects other schemes, relative paths and empty values', () => {
    expect(safeHref('javascript:alert(1)')).toBeUndefined()
    expect(safeHref('data:text/html,x')).toBeUndefined()
    expect(safeHref('file:///etc/passwd')).toBeUndefined()
    expect(safeHref('/local/path')).toBeUndefined()
    expect(safeHref('')).toBeUndefined()
    expect(safeHref(null)).toBeUndefined()
  })
})
