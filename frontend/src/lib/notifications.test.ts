import { describe, expect, it, vi } from 'vitest'
import { openNotification } from './notifications'
import type { Notification } from './api'

function note(overrides: Partial<Notification> = {}): Notification {
  return {
    id: 'n1', target_id: 't1', type: 'status_change', title: 'Status',
    body: 'changed', url: 'https://a.example', severity: 'medium',
    is_read: false, created_at: '2026-01-01 00:00:00', ...overrides,
  }
}

describe('openNotification', () => {
  it('opens the exact event in the shared Changes view', () => {
    const navigate = vi.fn()
    openNotification(note({ change_id: 'event-42' }), navigate, async () => [])
    expect(navigate).toHaveBeenCalledWith('/targets/t1?tab=monitor&event=event-42')
  })

  it('falls back to the first discovered host when no event id exists', () => {
    const navigate = vi.fn()
    openNotification(note({ metadata: { hosts: ['a.example', 'b.example'] } }), navigate, async () => [])
    expect(navigate).toHaveBeenCalledWith('/targets/t1?tab=monitor&q=a.example')
  })
})
