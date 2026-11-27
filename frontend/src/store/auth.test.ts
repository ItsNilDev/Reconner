import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore } from './auth'
import { useStatsStore } from './stats'
import { ws } from '../lib/websocket'
import type { DashboardStats } from '../types'

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify({ success: status < 400, data }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('auth store', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, initialized: false, loading: false })
    useStatsStore.getState().reset()
  })

  it('initializes to an anonymous state after an expired session', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ error: 'unauthorized' }, 401)))

    await useAuthStore.getState().checkAuth()

    expect(useAuthStore.getState()).toMatchObject({ user: null, initialized: true, loading: false })
  })

  it('loads the authenticated user after login and clears loading', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      calls.push(url)
      if (url.endsWith('/auth/login')) return response({ message: 'logged in' })
      return response({ id: 7, username: 'admin', role: 'admin', must_change_password: false })
    }))

    await useAuthStore.getState().login('admin', 'correct-password')

    expect(calls).toEqual(['/api/auth/login', '/api/auth/me'])
    expect(useAuthStore.getState()).toMatchObject({
      user: { id: 7, username: 'admin', role: 'admin' },
      loading: false,
    })
  })

  it('resets dashboard data on login so a second user never sees stale stats', async () => {
    const disconnect = vi.spyOn(ws, 'disconnect')
    useStatsStore.setState({
      badges: { targets: 42, running_tasks: 7 },
      stats: { targets: 42 } as DashboardStats,
      charts: {} as never,
      statsError: 'stale error',
    })
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/auth/login')) return response({ message: 'logged in' })
      return response({ id: 8, username: 'bob', role: 'member', must_change_password: false })
    }))

    await useAuthStore.getState().login('bob', 'correct-password')

    expect(useStatsStore.getState()).toMatchObject({
      badges: { targets: 0, running_tasks: 0 },
      stats: null,
      charts: null,
      statsError: '',
    })
    // A second login must also drop the old user's WS connection; the hub
    // authorizes by the userID captured at upgrade time.
    expect(disconnect).toHaveBeenCalledOnce()
    disconnect.mockRestore()
  })

  it('does not leave loading stuck when login fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'invalid credentials' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )))

    await expect(useAuthStore.getState().login('admin', 'wrong')).rejects.toThrow('invalid credentials')
    expect(useAuthStore.getState().loading).toBe(false)
  })
})
