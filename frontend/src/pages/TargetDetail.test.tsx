import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import TargetDetail from './TargetDetail'
import { ProgramLogo } from '../components/ui/ProgramLogo'
import { ws } from '../lib/websocket'
import type { Subdomain, Target } from '../types'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function pageResp<T>(data: T[], total: number, page = 1, limit = 200) {
  return new Response(JSON.stringify({ data, total, page, limit }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeTarget(overrides: Partial<Target> = {}): Target {
  return {
    id: 't1',
    domain: 'example.com',
    name: 'Acme Program',
    kind: 'web',
    description: '',
    tags: [],
    priority: 'medium',
    notes: '',
    status: 'active',
    scan_status: 'idle',
    enabled_modules: [],
    last_scan_at: null,
    created_at: '2026-11-26T00:00:00Z',
    updated_at: '2026-11-26T00:00:00Z',
    subdomain_count: 700,
    alive_host_count: 350,
    finding_count: 0,
    monitor_enabled: false,
    monitor_interval_hours: 12,
    monitor_last_run: null,
    program_logo_url: 'https://cdn.example.com/logo.png',
    ...overrides,
  }
}

function makeSubdomains(start: number, count: number): Subdomain[] {
  return Array.from({ length: count }, (_, idx) => {
    const n = start + idx
    return {
      id: `sub-${n}`,
      target_id: 't1',
      subdomain: `host-${n}.example.com`,
      ip: '192.0.2.1',
      is_alive: true,
      status_code: 200,
      page_title: `Title ${n}`,
      has_https: true,
      has_http: false,
      response_time_ms: 42,
      technologies: [],
      server: 'nginx',
      framework: '',
      cdn: '',
      waf: '',
      source: 'dns',
      last_seen: '2026-11-27T00:00:00Z',
      created_at: '2026-11-27T00:00:00Z',
    }
  })
}

function renderTargetDetail(initialPath = '/targets/t1') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/targets/:id" element={<TargetDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

function mockBaseEndpoints(
  onSubdomains: (url: URL, init?: RequestInit) => Promise<Response> | Response,
  targetOverrides: Partial<Target> = {},
) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const url = new URL(raw, 'http://localhost')
    if (url.pathname === '/api/targets/t1') return ok(makeTarget(targetOverrides))
    if (url.pathname === '/api/targets/t1/graph') return ok({ attack_paths: [] })
    if (url.pathname === '/api/targets/t1/assets') return ok([])
    if (url.pathname === '/api/targets/t1/watch-scope-events') return ok({ events: [] })
    if (url.pathname === '/api/targets/t1/bounty-events') return ok([])
    if (url.pathname === '/api/bounty/programs') return ok({ programs: [], total: 0, page: 1, limit: 50 })
    if (url.pathname === '/api/targets/t1/subdomains') return onSubdomains(url, init)
    throw new Error(`Unexpected fetch: ${url.pathname}${url.search}`)
  })
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('ProgramLogo', () => {
  it('validates http(s) URLs, cleans wildcard initials, and falls back on image error', () => {
    const { rerender, container } = render(
      <ProgramLogo src="javascript:alert(1)" name="https://*.example.com" size="sm" />,
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('E')).toBeInTheDocument()

    rerender(<ProgramLogo src="https://cdn.example.com/logo.png" name="Acme" size="md" />)
    const img = container.querySelector('img')
    expect(img).not.toBeNull()
    expect(img).toHaveAttribute('src', 'https://cdn.example.com/logo.png')
    expect(img).toHaveAttribute('referrerpolicy', 'no-referrer')

    fireEvent.error(img!)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('A')).toBeInTheDocument()
  })
})

describe('TargetDetail server-paged Hosts tab', () => {
  it('renders Page 1 immediately without fetching page 2+, and appends on Load more using offset', async () => {
    const subdomainQueries: string[] = []
    const fetchMock = mockBaseEndpoints((url) => {
      subdomainQueries.push(url.search)
      const limit = Number(url.searchParams.get('limit') || '200')
      const offset = Number(url.searchParams.get('offset') || '0')
      return pageResp(makeSubdomains(offset, limit), 700, 1, limit)
    })
    vi.stubGlobal('fetch', fetchMock)

    const { container } = renderTargetDetail()

    await screen.findByText('Showing 200 of 700')
    expect(screen.getByText('host-0.example.com')).toBeInTheDocument()
    expect(screen.getByText('host-199.example.com')).toBeInTheDocument()
    expect(screen.queryByText('host-200.example.com')).not.toBeInTheDocument()
    expect(subdomainQueries).toEqual(['?limit=200&page=1'])

    const heroImg = container.querySelector('img[src="https://cdn.example.com/logo.png"]')
    expect(heroImg).not.toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Load 200 more' }))
    await screen.findByText('Showing 400 of 700')
    expect(screen.getByText('host-200.example.com')).toBeInTheDocument()
    expect(screen.getByText('host-399.example.com')).toBeInTheDocument()
    expect(subdomainQueries).toEqual(['?limit=200&page=1', '?limit=200&offset=200'])
  }, 15000)

  it('streams Load all in 500-row chunks and aborts cleanly on Stop while keeping loaded rows', async () => {
    const subdomainQueries: string[] = []
    let abortedSecondChunk = false
    let resolvePendingChunk: (() => void) | null = null

    const fetchMock = mockBaseEndpoints((url, init) => {
      subdomainQueries.push(url.search)
      const limit = Number(url.searchParams.get('limit') || '200')
      const offset = Number(url.searchParams.get('offset') || '0')
      if (offset === 0) {
        return pageResp(makeSubdomains(0, 200), 1700, 1, limit)
      }
      if (offset === 200) {
        return pageResp(makeSubdomains(200, 500), 1700, 1, limit)
      }
      return new Promise<Response>((resolve, reject) => {
        const sig = init?.signal
        if (sig) {
          sig.addEventListener('abort', () => {
            abortedSecondChunk = true
            reject(new DOMException('Aborted', 'AbortError'))
          })
        }
        resolvePendingChunk = () => resolve(pageResp(makeSubdomains(700, 500), 1700, 1, limit))
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    renderTargetDetail()

    await screen.findByText('Showing 200 of 1,700')
    fireEvent.click(screen.getByRole('button', { name: 'Load all' }))

    await screen.findByText('Loading all… 700 / 1,700')
    expect(subdomainQueries).toEqual([
      '?limit=200&page=1',
      '?limit=500&offset=200',
      '?limit=500&offset=700',
    ])

    fireEvent.click(screen.getByRole('button', { name: 'Stop' }))

    await waitFor(() => expect(abortedSecondChunk).toBe(true))
    await screen.findByText('Showing 700 of 1,700')
    expect(screen.getByText('host-699.example.com')).toBeInTheDocument()
    expect(resolvePendingChunk).not.toBeNull()
  }, 15000)

  it('preserves loaded rows (>200) on WS task_progress and shows non-destructive Refresh banner', async () => {
    const wsHandlers = new Map<string, Set<(payload: unknown) => void>>()
    vi.spyOn(ws, 'on').mockImplementation((type, handler) => {
      if (!wsHandlers.has(type)) wsHandlers.set(type, new Set())
      wsHandlers.get(type)!.add(handler)
      return () => wsHandlers.get(type)?.delete(handler)
    })

    const subdomainQueries: string[] = []
    const fetchMock = mockBaseEndpoints((url) => {
      subdomainQueries.push(url.search)
      const limit = Number(url.searchParams.get('limit') || '200')
      const offset = Number(url.searchParams.get('offset') || '0')
      return pageResp(makeSubdomains(offset, limit), 700, 1, limit)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderTargetDetail()
    await screen.findByText('Showing 200 of 700')

    fireEvent.click(screen.getByRole('button', { name: 'Load 200 more' }))
    await screen.findByText('Showing 400 of 700')
    expect(subdomainQueries).toHaveLength(2)

    vi.useFakeTimers()
    act(() => {
      wsHandlers.get('task_progress')?.forEach(h =>
        h({ target_id: 't1', current_module: 'subdomain_enum' }),
      )
    })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3100)
    })

    expect(screen.getByText('Showing 400 of 700')).toBeInTheDocument()
    expect(screen.getByText('host-399.example.com')).toBeInTheDocument()
    expect(screen.getByText('New results available')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
    expect(subdomainQueries).toHaveLength(2)
  }, 15000)
})
