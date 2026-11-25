import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ChangeLog from './ChangeLog'
import { ws } from '../../lib/websocket'
import type { ChangeEntry } from '../../types'
import { parseStatusTransition } from './changesModel'

// Real default-feed rows: a watch host discovery, an alert notification and a
// program-scope row from the bounty feed.
const watchHost: ChangeEntry = {
  id: 'a1', source: 'watch', target_id: 't1', target_name: 'alpha.test',
  task_id: 'round-1', url: 'alpha.test', change_type: 'new_subdomain',
  category: 'assets', severity: 'info', seen: false,
  old_value: '', new_value: '1 new subdomain(s) found on alpha.test',
  metadata: { hosts: ['new.alpha.test'], total: 1 },
  detected_at: '2026-01-02 10:00:00',
}

const alertRow: ChangeEntry = {
  id: 'b1', source: 'monitor', target_id: 't1', target_name: 'alpha.test',
  task_id: '', url: 'https://alpha.test/alert', change_type: 'status_change', old_status: 403, new_status: 200,
  category: 'alerts', severity: 'medium', seen: false,
  old_value: '', new_value: 'Watch round failed',
  detected_at: '2026-01-03 10:00:00',
}

const bountyScope: ChangeEntry = {
  id: 'c1', source: 'bounty', target_id: 't2', target_name: 'beta.test',
  task_id: '', url: 'beta.test/scope', change_type: 'scope_modified',
  category: 'assets', severity: 'info', seen: false,
  old_value: JSON.stringify({ identifier: 'api.beta.test', in_scope: false }),
  new_value: JSON.stringify({ identifier: 'api.beta.test', in_scope: true }),
  program_id: 'Example Program',
  scope_status: 'approved',
  detected_at: '2026-01-04 10:00:00',
}

// None of these belong in the default view.
const noiseRows: ChangeEntry[] = [
  { ...watchHost, id: 'n1', change_type: 'status_change', category: 'http', url: 'https://alpha.test', metadata: undefined, new_value: 'status=200' },
  { ...alertRow, id: 'n2', change_type: 'finding', new_value: 'Finding text' },
  { ...watchHost, id: 'n3', source: 'monitor', change_type: 'tech_change', category: 'tech', task_id: '', metadata: undefined },
  { ...alertRow, id: 'n4', change_type: 'scan_deep' },
]

function envelope(data: unknown[]) {
  return new Response(JSON.stringify({ data, total: data.length, page: 1, limit: 200 }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

function success(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}

function callsFor(fetchMock: ReturnType<typeof vi.fn>, prefix: string) {
  return fetchMock.mock.calls.filter(([input]) => String(input).startsWith(prefix))
}

function changesCount(fetchMock: ReturnType<typeof vi.fn>) {
  return callsFor(fetchMock, '/api/changes?').length
}

function lastUrl(fetchMock: ReturnType<typeof vi.fn>, prefix: string): string {
  const calls = callsFor(fetchMock, prefix)
  return decodeURIComponent(String(calls[calls.length - 1][0]))
}

function lastChangesUrl(fetchMock: ReturnType<typeof vi.fn>): string {
  return lastUrl(fetchMock, '/api/changes?')
}

function lastSeenAllUrl(fetchMock: ReturnType<typeof vi.fn>): string {
  return lastUrl(fetchMock, '/api/changes/seen-all?')
}

function matchesDefaultView(r: ChangeEntry): boolean {
  if (r.source === 'watch' && r.change_type === 'new_subdomain') return true
  if ((r.source === 'watch' || r.source === 'monitor') &&
    (r.change_type === 'status_change' || r.change_type === 'http_change' || r.change_type === 'page_change')) {
    const parsed = parseStatusTransition(r.old_value || '', r.new_value || '')
    const oldCode = r.old_status || parsed.oldCode || 0
    const newCode = r.new_status || parsed.newCode || 0
    return oldCode >= 100 && oldCode <= 599 && newCode >= 100 && newCode <= 599 && oldCode !== newCode
  }
  if (r.source === 'bounty' || r.source === 'watch_scope') return true
  if (r.source === 'notification' && r.change_type === 'new_host') return true
  return false
}

function installFetch(options?: { rows?: ChangeEntry[]; firstChanges?: Promise<Response> }) {
  let changesCalls = 0
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith('/api/changes?')) {
      changesCalls++
      if (changesCalls === 1 && options?.firstChanges) return options.firstChanges
      const u = new URL(url, 'http://localhost')
      const allRows = options?.rows ?? [watchHost]
      const rows = u.searchParams.get('default_view') === '1'
        ? allRows.filter(matchesDefaultView)
        : allRows
      return envelope(rows)
    }
    if (url.startsWith('/api/watch/rounds?')) return envelope([])
    if (url.startsWith('/api/targets?')) return success([])
    return success([])
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

type WsHandler = (payload: unknown) => void

function captureWs() {
  const handlers = new Map<string, WsHandler[]>()
  const spy = vi.spyOn(ws, 'on').mockImplementation((type: string, handler: WsHandler) => {
    const list = handlers.get(type) ?? []
    list.push(handler)
    handlers.set(type, list)
    return () => {}
  })
  return {
    handlers,
    spy,
    fire(type: string) { (handlers.get(type) ?? []).forEach(h => h({})) },
  }
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('ChangeLog loading and refresh', () => {
  it('renders cards and clears the skeleton after the first load', async () => {
    installFetch()
    render(<ChangeLog />)
    expect(await screen.findByText('NEW HOST')).toBeInTheDocument()
    await vi.waitFor(() => {
      expect(document.querySelectorAll('.skeleton').length).toBe(0)
    })
  })

  it('coalesces a refresh triggered during the first load and still clears the skeleton', async () => {
    vi.useFakeTimers()
    const first = deferred<Response>()
    const fetchMock = installFetch({ firstChanges: first.promise, rows: [alertRow] })
    const wsMock = captureWs()
    render(<ChangeLog />)

    expect(document.querySelectorAll('.skeleton').length).toBeGreaterThan(0)
    wsMock.fire('task_finished')
    await vi.advanceTimersByTimeAsync(2500)
    // The refresh was folded into the in-flight load; no extra query yet.
    expect(changesCount(fetchMock)).toBe(1)

    first.resolve(envelope([watchHost]))
    // The follow-up refresh runs once the first load finishes.
    await vi.waitFor(() => expect(changesCount(fetchMock)).toBe(2))
    await vi.waitFor(() => expect(screen.getByText('STATUS CODE')).toBeInTheDocument())
    await vi.waitFor(() => {
      expect(document.querySelectorAll('.skeleton').length).toBe(0)
    })
  })

  it('reloads only on feed-write events, not on task_progress or scope_landed', async () => {
    vi.useFakeTimers()
    const fetchMock = installFetch()
    const wsMock = captureWs()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    const before = changesCount(fetchMock)
    wsMock.fire('task_progress')
    wsMock.fire('scope_landed')
    await vi.advanceTimersByTimeAsync(2500)
    expect(changesCount(fetchMock)).toBe(before)

    wsMock.fire('task_finished')
    wsMock.fire('changes_written')
    wsMock.fire('bounty_scope_change')
    await vi.advanceTimersByTimeAsync(2500)
    await vi.waitFor(() => expect(changesCount(fetchMock)).toBe(before + 1))

    await vi.advanceTimersByTimeAsync(5000)
    expect(changesCount(fetchMock)).toBe(before + 1)
  })

  it('does not poll the changes feed on a 30 second interval', async () => {
    vi.useFakeTimers()
    const fetchMock = installFetch()
    captureWs()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    const before = changesCount(fetchMock)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(changesCount(fetchMock)).toBe(before)
  })

  it('requests at most 20 watch rounds', async () => {
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())
    expect(lastUrl(fetchMock, '/api/watch/rounds?')).toContain('limit=20')
  })
})

describe('ChangeLog default feed', () => {
  it('requests default_view=1 in Daily signals mode and omits it for All history or category filters', async () => {
    const fetchMock = installFetch({ rows: [...noiseRows, bountyScope] })
    render(<ChangeLog />)

    expect(await screen.findByText('api.beta.test · Example Program · Scope modified.')).toBeInTheDocument()
    expect(lastChangesUrl(fetchMock)).toContain('default_view=1')
    expect(screen.queryByText('STATUS CODE')).not.toBeInTheDocument()
    expect(screen.queryByText('TECHNOLOGIES')).not.toBeInTheDocument()
    expect(screen.queryByText('FINDING')).not.toBeInTheDocument()
    expect(screen.queryByText('SCAN DEEP')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'All history' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).not.toContain('default_view=1'))
    expect(await screen.findByText('TECHNOLOGIES')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Daily signals' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('default_view=1'))

    fireEvent.click(screen.getByRole('button', { name: 'Scripts' }))
    await vi.waitFor(() => {
      expect(lastChangesUrl(fetchMock)).toContain('category=scripts')
      expect(lastChangesUrl(fetchMock)).not.toContain('default_view=1')
    })
  })

  it('only renders http(s) links and promotes bare hosts', async () => {
    installFetch({ rows: [bountyScope, { ...alertRow, url: 'javascript:alert(1)' }] })
    render(<ChangeLog />)
    expect(await screen.findByText('api.beta.test · Example Program · Scope modified.')).toBeInTheDocument()

    const hostLink = screen.getByText('beta.test/scope').closest('a')
    expect(hostLink).toHaveAttribute('href', 'https://beta.test/scope')
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull()
  })
})

describe('ChangeLog filter controls', () => {
  it('multi-selects categories and All resets the selection', async () => {
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Scripts' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('category=scripts'))

    fireEvent.click(screen.getByRole('button', { name: 'Alerts' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('category=scripts,alerts'))

    fireEvent.click(screen.getByRole('button', { name: 'All' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).not.toContain('category='))
  })

  it('sends status-only, class, exact codes and search as query params', async () => {
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Status changes only' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('status_only=1'))

    fireEvent.click(screen.getByRole('button', { name: '4xx' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('status_class=4'))

    fireEvent.change(screen.getByPlaceholderText('200,403'), { target: { value: '200,403' } })
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('status_code=200,403'))

    fireEvent.change(screen.getByPlaceholderText('Search changes…'), { target: { value: 'Forbidden' } })
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('q=Forbidden'))
  })

  it('drops invalid status codes instead of truncating them', async () => {
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    fireEvent.change(screen.getByPlaceholderText('200,403'), { target: { value: '20,2000,abc,403' } })
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('status_code=403'))
    expect(lastChangesUrl(fetchMock)).not.toContain('status_code=20,')

    fireEvent.change(screen.getByPlaceholderText('200,403'), { target: { value: '20,2000' } })
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).not.toContain('status_code='))
  })

  it('passes the new filters through to mark-all-read', async () => {
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Scripts' }))
    await vi.waitFor(() => expect(lastChangesUrl(fetchMock)).toContain('category=scripts'))

    fireEvent.click(screen.getByRole('button', { name: 'Status changes only' }))
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await vi.waitFor(() => {
      expect(lastSeenAllUrl(fetchMock)).toContain('category=scripts')
      expect(lastSeenAllUrl(fetchMock)).toContain('status_only=1')
    })
  })

  it('mark-all-read uses raw search text before the debounce settles', async () => {
    vi.useFakeTimers()
    const fetchMock = installFetch()
    render(<ChangeLog />)
    await vi.advanceTimersByTimeAsync(0)
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    // Type and click within the 300ms debounce window. The seen-all request
    // must carry the raw text, not the still-empty debounced value.
    fireEvent.change(screen.getByPlaceholderText('Search changes…'), { target: { value: 'Forbidden' } })
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))

    await vi.waitFor(() => {
      expect(lastSeenAllUrl(fetchMock)).toContain('q=Forbidden')
    })
  })
})

describe('ChangeLog scope event renderer', () => {
  // A legacy scope_landed bell row carries an asset snapshot as JSON in both
  // value fields. The feed must render it as a readable scope event in the
  // card and in the Details drawer, never as serialized payload.
  const legacyLanded: ChangeEntry = {
    id: 'legacy-landed', source: 'notification', target_id: 't3', target_name: 'legacy.test',
    task_id: '', url: 'api.legacy.test', change_type: 'scope_landed',
    category: 'assets', severity: 'info', seen: false,
    old_value: '{}',
    new_value: JSON.stringify({ identifier: 'api.legacy.test', in_scope: true, asset_type: 'domain' }),
    metadata: { identifier: 'api.legacy.test', in_scope: true },
    program_id: 'Example Program',
    scope_status: 'approved',
    detected_at: '2026-01-05 10:00:00',
  }

  it('shows a readable summary in the card and Details drawer without raw JSON', async () => {
    installFetch({ rows: [legacyLanded] })
    render(<MemoryRouter><ChangeLog /></MemoryRouter>)

    // Legacy notification rows are hidden in the default view. All history
    // exposes them so the renderer can be exercised.
    fireEvent.click(screen.getByRole('button', { name: 'Assets & scope' }))
    const summary = 'api.legacy.test · Example Program · Host landed.'
    expect(await screen.findByText(summary)).toBeInTheDocument()
    expect(screen.getByText('Approved')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('"identifier"')
    expect(document.body.textContent).not.toContain('"in_scope"')

    fireEvent.click(screen.getByRole('button', { name: 'Details' }))
    // The drawer repeats the formatted summary and shows no serialized payload.
    expect(screen.getAllByText(summary).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('In scope:').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('yes').length).toBeGreaterThanOrEqual(1)
    expect(document.body.textContent).not.toContain('"identifier"')
    expect(document.body.textContent).not.toContain('"in_scope"')
  })
})
