import { describe, expect, it } from 'vitest'
import {
  buildSandboxedPreviewDoc,
  diffCSSVisual,
  extractSafeColor,
  extractSafeVisualTile,
  hasUnsafeCSSValue,
  parseCSSRules,
  sanitizeCSSForPreview,
  synthesizeSpecimenHTML,
} from './cssDiffModel'

describe('cssDiffModel', () => {
  describe('parseCSSRules & diffCSSVisual', () => {
    it('resolves single-hop :root var(--*) custom properties into color swatches', () => {
      const oldCSS = `
        :root { --brand: #112233; --accent-rgb: rgb(10 20 30 / 0.8); }
        .btn { background-color: var(--brand); color: var(--accent-rgb); }
      `
      const newCSS = `
        :root { --brand: #445566; --accent-rgb: oklch(0.65 0.2 260); }
        .btn { background-color: var(--brand); color: var(--accent-rgb); }
      `
      const diff = diffCSSVisual(oldCSS, newCSS)
      expect(diff.tokenChanges).toHaveLength(2)
      expect(diff.tokenChanges.find(t => t.name === '--brand')).toMatchObject({
        oldColor: '#112233',
        newColor: '#445566',
      })
      expect(diff.tokenChanges.find(t => t.name === '--accent-rgb')).toMatchObject({
        oldColor: 'rgb(10 20 30 / 0.8)',
        newColor: 'oklch(0.65 0.2 260)',
      })

      // Rule using var(--brand) resolves against each snapshot's :root
      expect(extractSafeColor('background-color', 'var(--brand)', { '--brand': '#445566' })).toBe('#445566')
    })

    it('rejects named colors on non-color properties like font-family: "Peru Sans"', () => {
      expect(extractSafeColor('font-family', '"Peru Sans"')).toBeNull()
      expect(extractSafeColor('font-family', 'peru')).toBeNull()
      expect(extractSafeColor('--font-stack', '"Peru Sans"')).toBeNull()
      expect(extractSafeColor('color', 'peru')).toBe('peru')
      expect(extractSafeColor('border', '1px solid #3b82f6')).toBe('#3b82f6')
    })

    it('rejects url(), image-set(), cross-fade(), src(), expression(), and backslash escapes in main-DOM styles', () => {
      const hostileValues = [
        'url(https://evil.test/ping.png)',
        'url("https://evil.test/ping.png")',
        'image-set(url(a.png) 1x)',
        '-webkit-image-set(url(a.png) 1x)',
        'cross-fade(url(a.png), url(b.png))',
        'src("https://evil.test/x")',
        'expression(alert(1))',
        '\\75 rl(https://evil.test/x)',
        'linear-gradient(to right, #fff, url(https://evil.test/x))',
      ]
      for (const val of hostileValues) {
        expect(hasUnsafeCSSValue(val)).toBe(true)
        expect(extractSafeColor('background', val)).toBeNull()
        expect(extractSafeVisualTile('background', val)).toBeNull()
      }
    })

    it('parses clamped safe visual tiles for typography, radius, opacity, border, shadow, and color-only gradients', () => {
      expect(extractSafeVisualTile('font-size', '96px')).toEqual({ kind: 'font-size', px: 36 })
      expect(extractSafeVisualTile('font-size', '6px')).toEqual({ kind: 'font-size', px: 10 })
      expect(extractSafeVisualTile('font-weight', 'bold')).toEqual({ kind: 'font-weight', weight: 700 })
      expect(extractSafeVisualTile('border-radius', '999px')).toEqual({ kind: 'border-radius', px: 32 })
      expect(extractSafeVisualTile('opacity', '0.5')).toEqual({ kind: 'opacity', value: 0.5 })
      expect(extractSafeVisualTile('border', '12px dashed #ff0000')).toEqual({
        kind: 'border',
        widthPx: 6,
        style: 'dashed',
        color: '#ff0000',
      })
      expect(extractSafeVisualTile('box-shadow', '0 4px 12px rgba(0, 0, 0, 0.25)')).toEqual({
        kind: 'box-shadow',
        shadow: '0px 4px 12px rgba(0, 0, 0, 0.25)',
      })
      expect(
        extractSafeVisualTile('background', 'linear-gradient(90deg, #111 0%, #eee 100%)'),
      ).toEqual({
        kind: 'gradient',
        gradient: 'linear-gradient(90deg, #111 0%, #eee 100%)',
      })
    })

    it('handles nested @media, @layer, CSS nesting &, and marks @keyframes/@font-face non-synthesizable', () => {
      const css = `
        @layer components {
          @media (min-width: 768px) {
            .card {
              color: #111;
              &:hover { color: #222; }
            }
          }
        }
        @keyframes spin { from { opacity: 0; } to { opacity: 1; } }
        @font-face { font-family: "Test"; src: url(https://evil.test/f.woff2); }
      `
      const parsed = parseCSSRules(css)
      const card = parsed.rules.find(r => r.selector === '.card')
      expect(card).toBeDefined()
      expect(card?.atRule).toBe('@layer components > @media (min-width: 768px)')
      expect(card?.synthesizable).toBe(true)

      const hover = parsed.rules.find(r => r.selector === '.card:hover')
      expect(hover).toBeDefined()
      expect(hover?.declarations[0]).toEqual({ property: 'color', value: '#222' })

      const keyframeStep = parsed.rules.find(r => r.selector === 'from')
      expect(keyframeStep?.synthesizable).toBe(false)

      const fontFace = parsed.rules.find(r => r.selector === '@font-face')
      expect(fontFace?.synthesizable).toBe(false)
    })

    it('gracefully flushes unclosed trailing blocks from 256 KB truncated CSS', () => {
      const truncated = `
        .header { color: #111111; }
        @media (max-width: 600px) {
          .footer { background-color: #222222; border-radius: 8px
      `
      const parsed = parseCSSRules(truncated)
      expect(parsed.rules.find(r => r.selector === '.header')).toBeDefined()
      const footer = parsed.rules.find(r => r.selector === '.footer')
      expect(footer).toBeDefined()
      expect(footer?.atRule).toBe('@media (max-width: 600px)')
      expect(footer?.declarations).toEqual([
        { property: 'background-color', value: '#222222' },
        { property: 'border-radius', value: '8px' },
      ])
    })
  })

  describe('sanitizeCSSForPreview & buildSandboxedPreviewDoc (Security)', () => {
    it('blocks </STYLE> breakouts, @\\69 mport, \\75 rl(), image-set(), and @font-face', () => {
      const hostileCSS = `
        @\\69 mport "https://evil.test/leak.css";
        @import url("https://evil.test/leak2.css");
        @font-face { font-family: Evil; src: url("https://evil.test/font.woff2"); }
        .a {
          color: #22c55e;
          background: \\75 rl(https://evil.test/exfil.png);
          background-image: image-set("https://evil.test/a.png" 1x);
          mask-image: -webkit-image-set(url(https://evil.test/b.png) 1x);
          list-style-image: cross-fade(url(https://evil.test/c.png), #fff);
          width: expression(alert(1));
          content: "</STYLE><meta http-equiv=refresh content='0;url=https://evil.test'>";
          content: "</style\t/><script>alert(1)</script>";
        }
      `
      const safe = sanitizeCSSForPreview(hostileCSS)
      expect(safe).toContain('color: #22c55e')
      expect(safe.toLowerCase()).not.toContain('evil.test/leak')
      expect(safe.toLowerCase()).not.toContain('evil.test/font')
      expect(safe.toLowerCase()).not.toContain('evil.test/exfil')
      expect(safe.toLowerCase()).not.toContain('image-set')
      expect(safe.toLowerCase()).not.toContain('cross-fade')
      expect(safe.toLowerCase()).not.toContain('expression(')
      expect(safe).not.toMatch(/<\//)
      expect(safe).toContain('<\\/STYLE>')
      expect(safe).toContain('<\\/style')
    })

    it('blocks hostile selector attribute breakouts and non-allowlisted tags while unescaping Tailwind classes', () => {
      const html = synthesizeSpecimenHTML([
        'a[href="><meta http-equiv=\'refresh\' content=\'0;url=https://evil.test\'>"]',
        'script.evil',
        'iframe#frame',
        'meta.redir',
        'button.hover\\:bg-red-500\\/50',
      ])
      expect(html).not.toContain('http-equiv')
      expect(html).not.toContain('<script')
      expect(html).not.toContain('<iframe')
      expect(html).not.toContain('<meta')
      expect(html).toContain('<button class="hover:bg-red-500/50">')
    })

    it('caps synthesized specimen nodes at 30', () => {
      const many = Array.from({ length: 50 }, (_, i) => `.cls-${i}`)
      const html = synthesizeSpecimenHTML(many)
      expect(html).toContain('Changed selectors (30)')
      expect(html).not.toContain('cls-35')
    })

    it('places CSP meta strictly before <style> in buildSandboxedPreviewDoc', () => {
      const doc = buildSandboxedPreviewDoc('.btn { color: #3b82f6; }', ['.btn'], 'dark')
      const cspIdx = doc.indexOf(
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
      )
      const firstStyleIdx = doc.indexOf('<style>')
      expect(cspIdx).toBeGreaterThan(-1)
      expect(firstStyleIdx).toBeGreaterThan(cspIdx)
      expect(doc).toContain('isolation: isolate')
    })
  })
})
