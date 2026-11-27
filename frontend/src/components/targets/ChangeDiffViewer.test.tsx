import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ChangeDiffViewer } from './ChangeDiffViewer'
import { APIError, findings as findingsApi } from '../../lib/api'
import type { FileBodyResponse } from '../../types'

function makeBody(
  kind: 'css' | 'js',
  side: 'old' | 'current',
  content: string,
  hash: string,
  captured = true,
): FileBodyResponse {
  return {
    kind,
    url: `https://app.example.test/static/main.${kind}`,
    side,
    hash,
    size: content.length,
    content,
    captured,
  }
}

describe('ChangeDiffViewer', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('supports JS Prev/Next stepping, counter, j/k shortcuts, folding expansion, and Beautify toggle', async () => {
    const oldLines = [
      'const h1 = 1;',
      'const a = "old-one";',
      ...Array.from({ length: 10 }, (_, i) => `const keep${i} = ${i};`),
      'const b = "old-two";',
      'const tail = 99;',
    ].join('\n')
    const newLines = [
      'const h1 = 1;',
      'const a = "new-one";',
      ...Array.from({ length: 10 }, (_, i) => `const keep${i} = ${i};`),
      'const b = "new-two";',
      'const tail = 99;',
    ].join('\n')

    vi.spyOn(findingsApi, 'fileBody').mockImplementation((_t, _k, _u, side) =>
      Promise.resolve(
        side === 'old'
          ? makeBody('js', 'old', oldLines, 'aaaa1111aaaa1111')
          : makeBody('js', 'current', newLines, 'bbbb2222bbbb2222'),
      ),
    )

    const scrollSpy = vi.fn()
    Element.prototype.scrollIntoView = scrollSpy

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/main.js"
        kind="js"
        onClose={() => {}}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 1 / 2')
    })

    // Changes only folds the 10-line unchanged block (3 top + 4 hidden + 3 bottom)
    const expandBtn = screen.getByRole('button', { name: /4 unchanged lines \(expand\)/i })
    expect(expandBtn).toBeInTheDocument()
    fireEvent.click(expandBtn)
    expect(screen.queryByRole('button', { name: /unchanged lines \(expand\)/i })).not.toBeInTheDocument()
    expect(screen.getByText('const keep5 = 5;')).toBeInTheDocument()

    // Step Next via button and wrap around
    fireEvent.click(screen.getByRole('button', { name: /Next/i }))
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 2 / 2')
    expect(scrollSpy).toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: /Next/i }))
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 1 / 2')

    // Step Prev via button
    fireEvent.click(screen.getByRole('button', { name: /Prev/i }))
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 2 / 2')

    // Keyboard shortcuts j / k
    fireEvent.keyDown(window, { key: 'j' })
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 1 / 2')
    fireEvent.keyDown(window, { key: 'k' })
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 2 / 2')

    // Ctrl+j must NOT step
    fireEvent.keyDown(window, { key: 'j', ctrlKey: true })
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 2 / 2')

    // Typing inside an input must NOT step
    const dummyInput = document.createElement('input')
    document.body.appendChild(dummyInput)
    fireEvent.keyDown(dummyInput, { key: 'j' })
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 2 / 2')
    dummyInput.remove()

    // Beautify button toggles pressed state
    const beautifyBtn = screen.getByRole('button', { name: 'Beautify' })
    expect(beautifyBtn).toHaveAttribute('aria-pressed', 'false')
    fireEvent.click(beautifyBtn)
    expect(beautifyBtn).toHaveAttribute('aria-pressed', 'true')
  })

  it('detects raw-byte 256 KB truncation and stale snapshot hash mismatch', async () => {
    vi.spyOn(findingsApi, 'fileBody').mockImplementation((_t, _k, _u, side) =>
      Promise.resolve(
        side === 'old'
          ? makeBody('js', 'old', 'const same = 1;', '1111222233334444')
          : makeBody('js', 'current', 'const same = 1;', '5555666677778888'),
      ),
    )

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/main.js"
        kind="js"
        expectedOldHash="deadbeefdeadbeef"
        expectedNewHash="cafebabecafebabe"
        onClose={() => {}}
      />,
    )

    await waitFor(() => {
      expect(screen.getByText(/past the 256 KB capture cap/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/Only the latest snapshot pair is retained/i)).toBeInTheDocument()
  })

  it('handles 404 gracefully with a non-alarming empty state', async () => {
    vi.spyOn(findingsApi, 'fileBody').mockRejectedValue(
      new APIError(404, 'no capture for this asset'),
    )

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/missing.js"
        kind="js"
        onClose={() => {}}
      />,
    )

    await waitFor(() => {
      expect(screen.getByText(/No snapshot body captured yet/i)).toBeInTheDocument()
    })
  })

  it('shows CSS Visual swatches, Jump to code, and hardened sandboxed Preview iframes', async () => {
    const oldCSS = [
      ':root { --primary: #112233; }',
      '.hero { padding: 12px; color: #111111; }',
      '.btn { background-color: var(--primary); border-radius: 4px; }',
    ].join('\n')
    const newCSS = [
      ':root { --primary: #22c55e; }',
      '.hero { padding: 12px; color: #f8fafc; }',
      '.btn { background-color: var(--primary); border-radius: 12px; }',
    ].join('\n')

    vi.spyOn(findingsApi, 'fileBody').mockImplementation((_t, _k, _u, side) =>
      Promise.resolve(
        side === 'old'
          ? makeBody('css', 'old', oldCSS, 'aaaa1111bbbb2222')
          : makeBody('css', 'current', newCSS, 'cccc3333dddd4444'),
      ),
    )

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/main.css"
        kind="css"
        onClose={() => {}}
      />,
    )

    // Defaults to Visual tab for CSS with parseable diffs
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Visual' })).toHaveAttribute('aria-selected', 'true')
    })
    expect(screen.getByText(/Color changes/i)).toBeInTheDocument()
    expect(screen.getAllByText('--primary').length).toBeGreaterThanOrEqual(1)

    // Preview tab renders two hardened iframes
    fireEvent.click(screen.getByRole('tab', { name: 'Preview' }))
    const iframes = document.querySelectorAll('iframe')
    expect(iframes).toHaveLength(2)
    for (const frame of Array.from(iframes)) {
      expect(frame.getAttribute('sandbox')).toBe('')
      expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer')
      expect(frame.getAttribute('tabindex')).toBe('-1')
      expect(frame.className).toContain('pointer-events-none')
      const srcDoc = frame.getAttribute('srcdoc') || ''
      expect(srcDoc).toContain('default-src \'none\'; style-src \'unsafe-inline\'')
      expect(srcDoc.indexOf('Content-Security-Policy')).toBeLessThan(srcDoc.indexOf('<style>'))
    }

    // Back to Visual, click Jump to code on a selector card
    fireEvent.click(screen.getByRole('tab', { name: 'Visual' }))
    const jumpButtons = screen.getAllByRole('button', { name: 'Jump to code' })
    expect(jumpButtons.length).toBeGreaterThan(0)
    fireEvent.click(jumpButtons[0])

    expect(screen.getByRole('tab', { name: 'Code diff' })).toHaveAttribute('aria-selected', 'true')
    expect(document.querySelector('[data-active-change="true"]')).toBeInTheDocument()
  })

  it('hides Visual and Preview tabs when only one side is captured', async () => {
    vi.spyOn(findingsApi, 'fileBody').mockImplementation((_t, _k, _u, side) =>
      Promise.resolve(
        side === 'old'
          ? makeBody('css', 'old', '', 'aaaa1111bbbb2222', false)
          : makeBody('css', 'current', '.btn { color: red; }', 'cccc3333dddd4444', true),
      ),
    )

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/main.css"
        kind="css"
        onClose={() => {}}
      />,

    )

    await waitFor(() => {
      expect(screen.getByText(/Original content was not captured/i)).toBeInTheDocument()
    })
    expect(screen.queryByRole('tab', { name: 'Visual' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Preview' })).not.toBeInTheDocument()
  })
  it('shows formatting/whitespace-only banner when Beautify hides raw byte differences', async () => {
    const longPrefix = 'const pad="' + 'x'.repeat(520) + '";'
    const oldJS = longPrefix + 'const a=1;const b=2;'
    const newJS = longPrefix + 'const a=1;\nconst b=2;'

    vi.spyOn(findingsApi, 'fileBody').mockImplementation((_t, _k, _u, side) =>
      Promise.resolve(
        side === 'old'
          ? makeBody('js', 'old', oldJS, '1111aaaa1111aaaa')
          : makeBody('js', 'current', newJS, '2222bbbb2222bbbb'),
      ),
    )

    render(
      <ChangeDiffViewer
        targetId="t1"
        url="https://app.example.test/static/bundle.js"
        kind="js"
        onClose={() => {}}
      />,
    )

    await waitFor(() => {
      expect(screen.getByText(/Formatting\/whitespace-only difference/i)).toBeInTheDocument()
    })
    // Must NOT falsely claim 256 KB truncation since raw bytes differ
    expect(screen.queryByText(/256 KB capture cap/i)).not.toBeInTheDocument()

    // Switching to Raw reveals the diff
    fireEvent.click(screen.getByRole('button', { name: 'Switch to Raw' }))
    expect(screen.getByTestId('change-counter')).toHaveTextContent('Change 1 / 1')
  })
})
