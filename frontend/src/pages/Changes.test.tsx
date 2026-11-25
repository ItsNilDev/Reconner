import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Changes from './Changes'
import type { ChangeEntry, WatchRound } from '../types'
import { parseStatusTransition } from '../components/changes/changesModel'

const changeRows: ChangeEntry[] = [
  {
    id: 'c1', source: 'notification', target_id: 't1', target_name: 'alpha.test',
    task_id: 'round-1', url: 'alpha.test', change_type: 'new_host',
    category: 'assets', severity: 'info', seen: false,
    old_value: '', new_value: '1 new subdomain(s) found on alpha.test',
    metadata: { hosts: ['new.alpha.test'], total: 1 },
    detected_at: '2026-01-02 10:00:00',
  },
  {
    id: 'c2', source: 'bounty', target_id: 't2', target_name: 'beta.test',
    task_id: '', url: 'beta.test/scope', change_type: 'scope_modified',
    category: 'assets', severity: 'info', seen: false,
    old_value: JSON.stringify({ identifier: 'api.beta.test', in_scope: false }),
    new_value: JSON.stringify({ identifier: 'api.beta.test', in_scope: true }),
    program_id: 'Example Program',
    detected_at: '2026-01-01 09:00:00',
  },
  {
    id: 'c3', source: 'monitor', target_id: 't1', target_name: 'alpha.test',
    task_id: '', url: '', change_type: 'status_change', old_status: 403, new_status: 200,
    category: 'alerts', severity: 'high', seen: false,
    old_value: '', new_value: 'Watch round failed',
    detected_at: '2026-01-01 08:00:00',
  },
  // A real watch status flip: explicit status codes make it a default signal.
  // It also keeps the HTTP category chip meaningful.
  {
    id: 'c4', source: 'watch', target_id: 't1', target_name: 'alpha.test',
    task_id: 'round-1', url: 'https://alpha.test', change_type: 'status_change',
    category: 'http', severity: 'medium', seen: false,
    old_value: 'status=403 title=Forbidden', new_value: 'status=200 title=OK',
    detected_at: '2026-01-02 10:00:00',
  },
  {
    id: 'c5', source: 'monitor', target_id: 't2', target_name: 'beta.test',
    task_id: '', url: 'https://beta.test/app.js', change_type: 'js_change',
    category: 'scripts', severity: 'medium', seen: false,
    old_value: 'hash=aaa', new_value: 'hash=bbb',
    detected_at: '2026-01-01 09:00:00',
  },
]

const rounds: WatchRound[] = [
  {
    id: 'round-1', target_id: 't1', target_name: 'alpha.test', status: 'finished',
    error: '', started_at: '2026-01-02 09:59:00', finished_at: '2026-01-02 10:00:00',
    change_count: 1,
  },
]

const targetList = [
  { id: 't1', name: 'alpha.test', domain: 'alpha.test' },
  { id: 't2', name: 'beta.test', domain: 'beta.test' },
]

function envelope(data: unknown[]) {
  return new Response(JSON.stringify({ data, total: data.length, page: 1, limit: 500 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function success(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
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

function mockApi(opts?: { changes?: ChangeEntry[]; rounds?: WatchRound[] }) {
  const rows = (opts?.changes ?? changeRows).map(r => ({ ...r }))
  const roundRows = opts?.rounds ?? rounds
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/changes/seen' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body || '{}')) as { ids?: string[]; seen?: boolean }
      for (const row of rows) if (body.ids?.includes(row.id)) row.seen = !!body.seen
      return success({ updated: body.ids?.length || 0 })
    }
    if (url.startsWith('/api/changes/seen-all')) {
      rows.forEach(r => { r.seen = true })
      return success({ updated: rows.length })
    }
    if (url.startsWith('/api/changes?')) {
      const u = new URL(url, 'http://localhost')
      const cat = u.searchParams.get('category')
      const cats = cat ? cat.split(',').filter(c => c && c !== 'all') : []
      const hideSeen = u.searchParams.get('hide_seen') === '1'
      const defaultView = u.searchParams.get('default_view') === '1'
      let filtered = cats.length ? rows.filter(r => cats.includes(r.category)) : rows
      if (defaultView) filtered = filtered.filter(matchesDefaultView)
      return envelope(hideSeen ? filtered.filter(r => !r.seen) : filtered)
    }
    if (url.startsWith('/api/watch/rounds?')) return envelope(roundRows)
    if (url.startsWith('/api/targets?')) return success(targetList)
    return success([])
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

afterEach(() => { vi.unstubAllGlobals() })

describe('global Changes page', () => {
  it('renders a flat feed with field diffs and source badges', async () => {
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Changes' })
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('default_view=1'))).toBe(true)
    expect(await screen.findByText('NEW HOST')).toBeInTheDocument()
    expect(screen.getByText('api.beta.test · Example Program · Scope modified.')).toBeInTheDocument()
    expect(screen.getAllByText('STATUS CODE').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Watch').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Bounty').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Bell').length).toBeGreaterThan(0)
    expect(screen.getByText('In scope:')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('hash=aaa')
    expect(screen.queryByText('JAVASCRIPT')).not.toBeInTheDocument()
  })

  it('filters the feed by category chips with multi-select', async () => {
    const user = userEvent.setup()
    mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'HTTP' }))
    await waitFor(() => expect(screen.queryByText('JAVASCRIPT')).not.toBeInTheDocument())
    expect(screen.getByText('STATUS CODE')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Scripts' }))
    await waitFor(() => expect(screen.getByText('JAVASCRIPT')).toBeInTheDocument())
    expect(screen.getByText('STATUS CODE')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'HTTP' }))
    await waitFor(() => expect(screen.queryByText('STATUS CODE')).not.toBeInTheDocument())
    expect(screen.getByText('JAVASCRIPT')).toBeInTheDocument()
  })

  it('filters by round when a round chip is clicked', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    const roundButton = screen.getByRole('button', { name: /alpha\.test.*finished/ })
    fetchMock.mockClear()
    await user.click(roundButton)

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) =>
      String(input).includes('task_id=round-1'))).toBe(true)
    )
    expect(await screen.findByText('Clear')).toBeInTheDocument()
  })

  it('marks all read and hides seen cards', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) =>
      String(input).includes('/api/changes/seen-all'))).toBe(true)
    )

    await user.click(screen.getByLabelText('Hide seen'))
    expect(await screen.findByText('All changes are marked as seen.')).toBeInTheDocument()
  })

  it('shows an empty state when there are no changes', async () => {
    mockApi({ changes: [], rounds: [] })
    render(<MemoryRouter><Changes /></MemoryRouter>)
    expect(await screen.findByText('No changes recorded yet.')).toBeInTheDocument()
  })
})
