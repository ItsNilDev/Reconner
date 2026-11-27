import { describe, expect, it } from 'vitest'
import {
  beautifyCode,
  buildDiffBlocks,
  foldContextLines,
  normalizeNewlines,
  shouldAutoBeautify,
} from './diffModel'

describe('diffModel', () => {
  describe('normalizeNewlines & shouldAutoBeautify', () => {
    it('normalizes CRLF and lone CR to LF', () => {
      expect(normalizeNewlines('a\r\nb\rc\n')).toBe('a\nb\nc\n')
      expect(normalizeNewlines('')).toBe('')
    })

    it('detects minified code via max line length or high average line length', () => {
      const normal = 'const a = 1;\nconst b = 2;\n'
      expect(shouldAutoBeautify(normal, normal)).toBe(false)

      const longLine = 'const x = "' + 'a'.repeat(520) + '";'
      expect(shouldAutoBeautify(normal, longLine)).toBe(true)

      const highAvg = ['a'.repeat(350), 'b'.repeat(350), 'c'.repeat(350)].join('\n')
      expect(shouldAutoBeautify(highAvg, normal)).toBe(true)
    })
  })

  describe('beautifyCode (JS)', () => {
    it('disambiguates division from regex literals and preserves regex char classes', () => {
      const divInput = 'a=x/y;b=z/w;'
      const divRes = beautifyCode(divInput, 'js')
      expect(divRes.exceededCap).toBe(false)
      expect(divRes.text.split('\n')).toEqual(['a=x/y;', 'b=z/w;'])

      const regexInput = 'const r=/a;b[c/d]e/gi;const x=1;'
      const regexRes = beautifyCode(regexInput, 'js')
      expect(regexRes.text.split('\n')).toEqual([
        'const r=/a;b[c/d]e/gi;',
        'const x=1;',
      ])

      const controlRegex = 'if(ok)/foo;bar/.test(s);done();'
      const ctrlRes = beautifyCode(controlRegex, 'js')
      expect(ctrlRes.text).toContain('/foo;bar/.test(s);')
      expect(ctrlRes.text.split('\n').length).toBe(2)
    })

    it('handles nested template literals and object braces inside ${...}', () => {
      const src = 'const s=`outer ${fn(`a;b`)} ${{k:1}.k} end`;const t=2;'
      const res = beautifyCode(src, 'js')
      expect(res.exceededCap).toBe(false)
      expect(res.text.split('\n')).toEqual([
        'const s=`outer ${fn(`a;b`)} ${{k:1}.k} end`;',
        'const t=2;',
      ])
    })

    it('does not split semicolons inside for(...) headers', () => {
      const src = 'for(let i=0;i<n;i++){sum+=i;log(i);}'
      const res = beautifyCode(src, 'js')
      expect(res.text).toBe(
        [
          'for(let i=0; i<n; i++){',
          '  sum+=i;',
          '  log(i);',
          '}',
        ].join('\n'),
      )
    })

    it('terminates gracefully on EOF-truncated strings, comments, and templates', () => {
      const truncString = 'const a=1;const s="unterminated tail past 256kb'
      expect(() => beautifyCode(truncString, 'js')).not.toThrow()
      expect(beautifyCode(truncString, 'js').text).toContain('"unterminated tail past 256kb')

      const truncComment = 'const a=1;/* unclosed comment at EOF'
      expect(() => beautifyCode(truncComment, 'js')).not.toThrow()
      expect(beautifyCode(truncComment, 'js').text).toContain('/* unclosed comment at EOF')

      const truncTemplate = 'const a=1;const t=`unclosed ${foo'
      expect(() => beautifyCode(truncTemplate, 'js')).not.toThrow()
      expect(beautifyCode(truncTemplate, 'js').text).toContain('`unclosed ${foo')
    })

    it('enforces maxLines cap and returns normalized original when exceeded', () => {
      const big = Array.from({ length: 30 }, (_, i) => `x${i}=${i};`).join('')
      const res = beautifyCode(big, 'js', 10)
      expect(res.exceededCap).toBe(true)
      expect(res.text).toBe(big)
    })
  })

  describe('beautifyCode (CSS)', () => {
    it('formats minified CSS with indentation while keeping parens/strings/comments intact', () => {
      const css = '@media (min-width:768px){.btn{color:#fff;background:url("data:image/svg+xml;base64,abc");/* keep */}}'
      const res = beautifyCode(css, 'css')
      expect(res.exceededCap).toBe(false)
      expect(res.text).toBe(
        [
          '@media (min-width:768px) {',
          '  .btn {',
          '    color:#fff;',
          '    background:url("data:image/svg+xml;base64,abc");',
          '    /* keep */',
          '  }',
          '}',
        ].join('\n'),
      )
    })

    it('handles EOF-truncated CSS comments and respects maxLines', () => {
      const trunc = '.a{color:red;/* unclosed comment'
      expect(beautifyCode(trunc, 'css').text).toContain('/* unclosed comment')

      const big = Array.from({ length: 20 }, (_, i) => `.c${i}{color:red;}`).join('')
      const capped = beautifyCode(big, 'css', 8)
      expect(capped.exceededCap).toBe(true)
      expect(capped.text).toBe(big)
    })
  })

  describe('buildDiffBlocks', () => {
    it('merges adjacent removed+added chunks into single change hunks with 1-based line numbers', () => {
      const oldText = ['line1', 'oldA', 'line3', 'line4', 'oldB', 'line6'].join('\n')
      const newText = ['line1', 'newA1', 'newA2', 'line3', 'line4', 'newB', 'line6'].join('\n')

      const res = buildDiffBlocks(oldText, newText)
      expect(res.simplified).toBe(false)
      expect(res.totalChanges).toBe(2)
      expect(res.removedLines).toBe(2)
      expect(res.addedLines).toBe(3)

      const changes = res.blocks.filter(b => b.kind === 'change')
      expect(changes).toHaveLength(2)
      expect(changes[0].kind === 'change' && changes[0].changeIndex).toBe(0)
      expect(changes[0].lines).toEqual([
        { kind: 'removed', text: 'oldA', oldLine: 2, newLine: null },
        { kind: 'added', text: 'newA1', oldLine: null, newLine: 2 },
        { kind: 'added', text: 'newA2', oldLine: null, newLine: 3 },
      ])
      expect(changes[1].kind === 'change' && changes[1].changeIndex).toBe(1)
      expect(changes[1].lines).toEqual([
        { kind: 'removed', text: 'oldB', oldLine: 5, newLine: null },
        { kind: 'added', text: 'newB', oldLine: null, newLine: 6 },
      ])
    })

    it('normalizes CRLF so newline-only changes produce zero hunks', () => {
      const res = buildDiffBlocks('a\r\nb\r\nc\r\n', 'a\nb\nc\n')
      expect(res.totalChanges).toBe(0)
      expect(res.addedLines).toBe(0)
      expect(res.removedLines).toBe(0)
    })

    it('handles empty inputs without bogus empty lines', () => {
      expect(buildDiffBlocks('', '').blocks).toEqual([])
      const addedOnly = buildDiffBlocks('', 'hello\n')
      expect(addedOnly.totalChanges).toBe(1)
      expect(addedOnly.addedLines).toBe(1)
      expect(addedOnly.removedLines).toBe(0)
    })

    it('falls back to O(N) prefix/suffix simplified diff when diffLines aborts', () => {
      const oldText = ['same-top', 'a1', 'a2', 'a3', 'same-bottom'].join('\n')
      const newText = ['same-top', 'b1', 'b2', 'b3', 'same-bottom'].join('\n')

      const res = buildDiffBlocks(oldText, newText, { maxEditLength: 1 })
      expect(res.simplified).toBe(true)
      expect(res.totalChanges).toBe(1)
      expect(res.removedLines).toBe(3)
      expect(res.addedLines).toBe(3)
      expect(res.blocks).toHaveLength(3)
      expect(res.blocks[0]).toEqual({
        kind: 'context',
        lines: [{ kind: 'context', text: 'same-top', oldLine: 1, newLine: 1 }],
      })
      expect(res.blocks[2]).toEqual({
        kind: 'context',
        lines: [{ kind: 'context', text: 'same-bottom', oldLine: 5, newLine: 5 }],
      })
    })
  })

  describe('foldContextLines', () => {
    const makeLines = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        kind: 'context' as const,
        text: `line ${i + 1}`,
        oldLine: i + 1,
        newLine: i + 1,
      }))

    it('keeps short context runs unfolded when length <= 2 * radius', () => {
      const folded = foldContextLines(makeLines(6), 3)
      expect(folded.collapsed).toBe(false)
      expect(folded.top).toHaveLength(6)
      expect(folded.hidden).toHaveLength(0)
      expect(folded.bottom).toHaveLength(0)
    })

    it('splits long context runs into top, hidden, and bottom segments', () => {
      const folded = foldContextLines(makeLines(12), 3)
      expect(folded.collapsed).toBe(true)
      expect(folded.top.map(l => l.oldLine)).toEqual([1, 2, 3])
      expect(folded.hidden.map(l => l.oldLine)).toEqual([4, 5, 6, 7, 8, 9])
      expect(folded.bottom.map(l => l.oldLine)).toEqual([10, 11, 12])
    })
  })
})
