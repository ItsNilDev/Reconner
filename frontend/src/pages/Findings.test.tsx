import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Findings from './Findings'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const finding = {
  id: 'f1', target_id: 't1', domain: 'example.test', type: 'sqli', severity: 'high',
  url: 'https://example.test/?id=1', parameter: 'id', payload: "1' AND (1=1)-- -",
  confidence: 95, priority: 10, status: 'finding',
  evidence: 'DB error triggered by boundary (reproduced; absent from baseline)',
  created_at: new Date().toISOString(),
}

function LocationEcho() {
  const loc = useLocation()
  return <div data-testid="location">{loc.pathname}{loc.search}</div>
}

// The global Findings page must surface the reproduction payload directly (not
// force the reviewer to open the target detail view first), and clicking the
// PoC toggle or copy button must not navigate the row away.
describe('Findings payload/PoC surfacing', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('shows the payload inline and expands full payload + evidence without navigating away', async () => {
    const fetchMock = vi.fn(async () => ok([finding]))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><Findings /></MemoryRouter>)
    await screen.findByText('sqli')

    // Truncated payload is visible inline in the table row.
    expect(screen.getByTitle("1' AND (1=1)-- -")).toBeInTheDocument()

    // Expanding shows the full payload and evidence.
    await user.click(screen.getByText('PoC'))
    await waitFor(() => expect(screen.getByText('Evidence')).toBeInTheDocument())
    expect(screen.getAllByText("1' AND (1=1)-- -").length).toBeGreaterThan(1)
    expect(screen.getByText(/DB error triggered by boundary/)).toBeInTheDocument()

    // Collapsing works too.
    await user.click(screen.getByText('hide'))
    await waitFor(() => expect(screen.queryByText('Evidence')).not.toBeInTheDocument())
  })

  it('deep-links rows to the matching target tab and renders source pills and filters', async () => {
    const nativeFinding = { ...finding, id: 'f-native', target_id: 't1', source: 'native', source_tab: 'vulns' }
    const nucleiFinding = {
      ...finding, id: 'f-nuclei', target_id: 't2', domain: 'api.example.test',
      type: 'cve-2024-0001', severity: 'critical', url: 'https://api.example.test/admin',
      parameter: '', payload: '', evidence: 'matched template',
      source: 'nuclei', source_tab: 'nuclei',
    }
    const requestedUrls: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)
      if (url.startsWith('/api/targets')) {
        return ok([
          { id: 't1', domain: 'example.test', name: 'Example' },
          { id: 't2', domain: 'api.example.test', name: 'API' },
        ])
      }
      return new Response(JSON.stringify({
        success: true,
        data: [nativeFinding, nucleiFinding],
        total: 2,
        page: 1,
        limit: 200,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(
      <MemoryRouter initialEntries={['/findings']}>
        <Routes>
          <Route path="/findings" element={<Findings />} />
          <Route path="/targets/:id" element={<LocationEcho />} />
        </Routes>
      </MemoryRouter>,
    )

    await screen.findByText('cve-2024-0001')
    expect(screen.getByPlaceholderText('Search host, URL, type, parameter…')).toBeInTheDocument()
    expect(screen.getAllByText('Nuclei').length).toBeGreaterThanOrEqual(2)

    await user.selectOptions(screen.getByLabelText('Filter by source'), 'nuclei')
    await waitFor(() => expect(requestedUrls.some(u => u.includes('source=nuclei'))).toBe(true))

    await user.click(screen.getByText('cve-2024-0001'))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/targets/t2?tab=nuclei'))
  })

  it('deep-links native findings to ?tab=vulns and supports inline Mark FP triage', async () => {
    const secondFinding = { ...finding, id: 'f2', type: 'xss', url: 'https://example.test/?q=1' }
    const triageCalls: { url: string; body: unknown }[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/triage') && init?.method === 'POST') {
        triageCalls.push({ url, body: JSON.parse(String(init.body)) })
        return ok({ triage: 'false_positive' })
      }
      if (url.startsWith('/api/targets')) return ok([])
      return ok([finding, secondFinding])
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(
      <MemoryRouter initialEntries={['/findings']}>
        <Routes>
          <Route path="/findings" element={<Findings />} />
          <Route path="/targets/:id" element={<LocationEcho />} />
        </Routes>
      </MemoryRouter>,
    )

    await screen.findByText('sqli')
    await user.click(screen.getAllByText('PoC')[0])
    await waitFor(() => expect(screen.getByRole('button', { name: 'Mark FP' })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Mark FP' }))
    await waitFor(() => expect(triageCalls).toHaveLength(1))
    expect(triageCalls[0].url).toBe('/api/targets/t1/findings/f1/triage')
    expect(triageCalls[0].body).toEqual({ triage: 'false_positive', note: '' })
    await waitFor(() => expect(screen.queryByText('sqli')).not.toBeInTheDocument())

    // Expand remaining native finding and follow its deep-link to ?tab=vulns.
    await user.click(screen.getByText('PoC'))
    await user.click(screen.getByRole('button', { name: 'Open in target →' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/targets/t1?tab=vulns'))
  })

  it('discards stale loadMore response when status changes mid-flight', async () => {
    const page1 = Array.from({ length: 200 }, (_, i) => ({
      ...finding,
      id: `f-${i}`,
      type: i === 0 ? 'initial_sqli' : 'other_sqli',
    }))
    const candidateRow = {
      ...finding,
      id: 'cand-1',
      type: 'candidate_ssrf',
      status: 'candidate',
    }
    let resolveStaleLoadMore!: (res: Response) => void
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.startsWith('/api/targets')) return Promise.resolve(ok([]))
      if (url.includes('status=candidate')) {
        return Promise.resolve(new Response(JSON.stringify({
          success: true, data: [candidateRow], total: 1, page: 1, limit: 200,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      }
      if (url.includes('offset=200')) {
        return new Promise<Response>(resolve => { resolveStaleLoadMore = resolve })
      }
      return Promise.resolve(new Response(JSON.stringify({
        success: true, data: page1, total: 250, page: 1, limit: 200,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><Findings /></MemoryRouter>)
    await screen.findByText('initial_sqli')
    expect(screen.getByRole('button', { name: 'Load more' })).toBeInTheDocument()

    // Start loadMore and leave it pending while switching status to Needs Review.
    await user.click(screen.getByRole('button', { name: 'Load more' }))
    await waitFor(() => expect(resolveStaleLoadMore).toBeTypeOf('function'))

    await user.click(screen.getByRole('button', { name: 'Needs Review' }))
    await screen.findByText('candidate_ssrf')
    expect(screen.queryByText('initial_sqli')).not.toBeInTheDocument()

    // Resolve the stale loadMore response — it must be ignored completely.
    resolveStaleLoadMore(new Response(JSON.stringify({
      success: true,
      data: [{ ...finding, id: 'f-stale', type: 'stale_finding' }],
      total: 250,
      page: 2,
      limit: 200,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await new Promise(r => setTimeout(r, 20))
    expect(screen.queryByText('stale_finding')).not.toBeInTheDocument()
    expect(screen.getByText('candidate_ssrf')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /All\s+1/ })).toBeInTheDocument()
  })

  it('passes current row count as offset after Mark FP and hides Load more on short page', async () => {
    const page1 = Array.from({ length: 200 }, (_, i) => ({
      ...finding,
      id: `f-${i}`,
      type: i === 0 ? 'first_sqli' : 'other_sqli',
    }))
    const requestedUrls: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      requestedUrls.push(url)
      if (url.includes('/triage') && init?.method === 'POST') {
        return ok({ triage: 'false_positive' })
      }
      if (url.startsWith('/api/targets')) return ok([])
      if (url.includes('offset=')) {
        return new Response(JSON.stringify({
          success: true,
          data: [{ ...finding, id: 'f-tail', type: 'tail_xss' }],
          total: 205,
          page: 2,
          limit: 200,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        success: true, data: page1, total: 202, page: 1, limit: 200,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><Findings /></MemoryRouter>)
    await screen.findByText('first_sqli')
    expect(screen.getByText('Showing 200 of 202')).toBeInTheDocument()

    await user.click(screen.getAllByText('PoC')[0])
    await user.click(screen.getByRole('button', { name: 'Mark FP' }))
    await waitFor(() => expect(screen.queryByText('first_sqli')).not.toBeInTheDocument())
    expect(screen.getByText('Showing 199 of 201')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Load more' }))
    await screen.findByText('tail_xss')

    expect(requestedUrls.some(u => u.includes('offset=199'))).toBe(true)
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument()
  })

  it('sends severity query param when clicking a severity pill and resets it via Clear', async () => {
    const page1 = Array.from({ length: 200 }, (_, i) => ({
      ...finding,
      id: `crit-${i}`,
      severity: 'critical',
      type: i === 0 ? 'crit_rce' : 'other_crit',
    }))
    const mediumRow = {
      ...finding,
      id: 'med-1',
      severity: 'medium',
      type: 'med_redirect',
    }
    const requestedUrls: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)
      if (url.startsWith('/api/targets')) return ok([])
      if (url.includes('severity=medium')) {
        return new Response(JSON.stringify({
          success: true, data: [mediumRow], total: 1, page: 1, limit: 200,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({
        success: true, data: page1, total: 250, page: 1, limit: 200,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()

    render(<MemoryRouter><Findings /></MemoryRouter>)
    await screen.findByText('crit_rce')

    // Even with 0 loaded medium rows, medium pill stays enabled while more pages exist.
    const mediumBtn = screen.getByRole('button', { name: /^medium/i })
    expect(mediumBtn).not.toBeDisabled()
    await user.click(mediumBtn)

    await screen.findByText('med_redirect')
    expect(requestedUrls.some(u => u.includes('/api/findings?') && u.includes('severity=medium'))).toBe(true)
    expect(screen.getByRole('button', { name: /^low/i })).not.toBeDisabled()

    const clearBtn = screen.getByRole('button', { name: 'Clear' })
    await user.click(clearBtn)

    await screen.findByText('crit_rce')
    const findingsCalls = requestedUrls.filter(u => u.startsWith('/api/findings'))
    expect(findingsCalls[findingsCalls.length - 1]).not.toContain('severity=')
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument()
  })
})
