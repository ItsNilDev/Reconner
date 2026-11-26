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
    const triageCalls: { url: string; body: unknown }[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/triage') && init?.method === 'POST') {
        triageCalls.push({ url, body: JSON.parse(String(init.body)) })
        return ok({ triage: 'false_positive' })
      }
      if (url.startsWith('/api/targets')) return ok([])
      return ok([finding])
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
    await user.click(screen.getByText('PoC'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Mark FP' })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Mark FP' }))
    await waitFor(() => expect(triageCalls).toHaveLength(1))
    expect(triageCalls[0].url).toBe('/api/targets/t1/findings/f1/triage')
    expect(triageCalls[0].body).toEqual({ triage: 'false_positive', note: '' })
    await waitFor(() => expect(screen.queryByText('sqli')).not.toBeInTheDocument())
  })
})
