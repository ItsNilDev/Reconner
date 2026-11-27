// Pure CSS visual diff engine & hardened sandboxed preview generator.
// Zero reliance on CSS.supports (unavailable in jsdom and unsafe as a security
// filter) and zero external network fetches.
//
// Security note: Reconner's SPA sets no HTTP CSP header, so main-DOM visual
// previews strictly validate every value against per-property allowlists and
// NEVER pass raw untrusted CSS strings into React `style`. Sandboxed Preview
// iframes use `sandbox=""`, `referrerPolicy="no-referrer"`, an inline CSP
// `<meta>` placed strictly before `<style>`, comment/escape-aware CSS stripping,
// and unconditional `</` -> `<\/` escaping. Upstream reverse-proxy CSP must
// permit `style-src 'unsafe-inline'` for Preview styles to render since
// `about:srcdoc` inherits parent CSP.

export interface CSSDeclaration {
  property: string
  value: string
}

export interface CSSParsedRule {
  atRule: string
  selector: string
  declarations: CSSDeclaration[]
  synthesizable: boolean
}

export interface CSSParseResult {
  rules: CSSParsedRule[]
  rootVars: Record<string, string>
}

export type SafeVisualTile =
  | { kind: 'color'; color: string }
  | { kind: 'gradient'; gradient: string }
  | { kind: 'font-size'; px: number }
  | { kind: 'font-weight'; weight: number }
  | { kind: 'border-radius'; px: number }
  | { kind: 'opacity'; value: number }
  | { kind: 'border'; widthPx: number; style: 'solid' | 'dashed' | 'dotted' | 'double'; color: string }
  | { kind: 'box-shadow'; shadow: string }

export type CSSDeclChangeStatus = 'added' | 'removed' | 'changed'

export interface CSSColorChange {
  id: string
  selector: string
  atRule: string
  property: string
  status: CSSDeclChangeStatus
  oldRaw: string | null
  newRaw: string | null
  oldColor: string | null
  newColor: string | null
}

export interface CSSTokenChange {
  name: string
  selector: string
  atRule: string
  status: CSSDeclChangeStatus
  oldRaw: string | null
  newRaw: string | null
  oldColor: string | null
  newColor: string | null
}

export interface CSSSelectorDeclDiff {
  property: string
  status: CSSDeclChangeStatus
  oldRaw: string | null
  newRaw: string | null
  oldTile: SafeVisualTile | null
  newTile: SafeVisualTile | null
}

export interface CSSSelectorDiff {
  atRule: string
  selector: string
  synthesizable: boolean
  declarations: CSSSelectorDeclDiff[]
}

export interface CSSVisualDiff {
  colorChanges: CSSColorChange[]
  tokenChanges: CSSTokenChange[]
  selectorDiffs: CSSSelectorDiff[]
  changedSelectors: string[]
  hasVisualDiffs: boolean
}

// Standard CSS Color 4 named colors + transparent.
const CSS_NAMED_COLORS: Record<string, true> = {
  aliceblue: true, antiquewhite: true, aqua: true, aquamarine: true, azure: true,
  beige: true, bisque: true, black: true, blanchedalmond: true, blue: true,
  blueviolet: true, brown: true, burlywood: true, cadetblue: true, chartreuse: true,
  chocolate: true, coral: true, cornflowerblue: true, cornsilk: true, crimson: true,
  cyan: true, darkblue: true, darkcyan: true, darkgoldenrod: true, darkgray: true,
  darkgreen: true, darkgrey: true, darkkhaki: true, darkmagenta: true, darkolivegreen: true,
  darkorange: true, darkorchid: true, darkred: true, darksalmon: true, darkseagreen: true,
  darkslateblue: true, darkslategray: true, darkslategrey: true, darkturquoise: true, darkviolet: true,
  deeppink: true, deepskyblue: true, dimgray: true, dimgrey: true, dodgerblue: true,
  firebrick: true, floralwhite: true, forestgreen: true, fuchsia: true, gainsboro: true,
  ghostwhite: true, gold: true, goldenrod: true, gray: true, green: true,
  greenyellow: true, grey: true, honeydew: true, hotpink: true, indianred: true,
  indigo: true, ivory: true, khaki: true, lavender: true, lavenderblush: true,
  lawngreen: true, lemonchiffon: true, lightblue: true, lightcoral: true, lightcyan: true,
  lightgoldenrodyellow: true, lightgray: true, lightgreen: true, lightgrey: true, lightpink: true,
  lightsalmon: true, lightseagreen: true, lightskyblue: true, lightslategray: true, lightslategrey: true,
  lightsteelblue: true, lightyellow: true, lime: true, limegreen: true, linen: true,
  magenta: true, maroon: true, mediumaquamarine: true, mediumblue: true, mediumorchid: true,
  mediumpurple: true, mediumseagreen: true, mediumslateblue: true, mediumspringgreen: true, mediumturquoise: true,
  mediumvioletred: true, midnightblue: true, mintcream: true, mistyrose: true, moccasin: true,
  navajowhite: true, navy: true, oldlace: true, olive: true, olivedrab: true,
  orange: true, orangered: true, orchid: true, palegoldenrod: true, palegreen: true,
  paleturquoise: true, palevioletred: true, papayawhip: true, peachpuff: true, peru: true,
  pink: true, plum: true, powderblue: true, purple: true, rebeccapurple: true,
  red: true, rosybrown: true, royalblue: true, saddlebrown: true, salmon: true,
  sandybrown: true, seagreen: true, seashell: true, sienna: true, silver: true,
  skyblue: true, slateblue: true, slategray: true, slategrey: true, snow: true,
  springgreen: true, steelblue: true, tan: true, teal: true, thistle: true,
  tomato: true, transparent: true, turquoise: true, violet: true, wheat: true,
  white: true, whitesmoke: true, yellow: true, yellowgreen: true,
}

const GROUPING_AT_RULES: Record<string, true> = {
  media: true,
  supports: true,
  layer: true,
  container: true,
  scope: true,
  document: true,
  'starting-style': true,
}

const KEYFRAME_AT_RULES: Record<string, true> = {
  keyframes: true,
  '-webkit-keyframes': true,
  '-moz-keyframes': true,
  '-o-keyframes': true,
}

const DECLARATION_AT_RULES: Record<string, true> = {
  'font-face': true,
  page: true,
  property: true,
  'counter-style': true,
  'font-palette-values': true,
  viewport: true,
}

const ALLOWED_SPECIMEN_TAGS: Record<string, true> = {
  div: true, span: true, p: true, a: true, button: true, input: true,
  h1: true, h2: true, h3: true, h4: true, h5: true, h6: true,
  ul: true, li: true, table: true, tr: true, td: true, th: true,
  nav: true, header: true, main: true, section: true, article: true, label: true,
}

const BORDER_STYLES: Record<string, 'solid' | 'dashed' | 'dotted' | 'double'> = {
  solid: 'solid',
  dashed: 'dashed',
  dotted: 'dotted',
  double: 'double',
}

const MAX_SYNTHESIZED_NODES = 30

function hasOwn(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

export function stripCSSComments(css: string): string {
  if (!css) return ''
  let out = ''
  let i = 0
  const len = css.length
  let inQuote: string | null = null
  while (i < len) {
    const ch = css[i]
    if (inQuote) {
      out += ch
      if (ch === '\\' && i + 1 < len) {
        out += css[i + 1]
        i += 2
        continue
      }
      if (ch === inQuote) inQuote = null
      i++
      continue
    }
    if (ch === '\'' || ch === '"') {
      inQuote = ch
      out += ch
      i++
      continue
    }
    if (ch === '/' && i + 1 < len && css[i + 1] === '*') {
      i += 2
      while (i < len) {
        if (css[i] === '*' && i + 1 < len && css[i + 1] === '/') {
          i += 2
          break
        }
        i++
      }
      continue
    }
    out += ch
    i++
  }
  return out
}

// Decode CSS backslash escapes (both `\HH..H ` hex escapes and `\X` char escapes)
// for security inspection and CSS class unescaping.
export function decodeCSSEscapes(input: string): string {
  if (!input.includes('\\')) return input
  let out = ''
  let i = 0
  const len = input.length
  while (i < len) {
    const ch = input[i]
    if (ch !== '\\') {
      out += ch
      i++
      continue
    }
    if (i + 1 >= len) {
      i++
      break
    }
    // Check 1-6 hex digits followed by optional single whitespace
    const hexMatch = /^[0-9a-fA-F]{1,6}[ \t\r\n\f]?/.exec(input.slice(i + 1))
    if (hexMatch) {
      const codePoint = parseInt(hexMatch[0].trim(), 16)
      if (codePoint > 0 && codePoint <= 0x10ffff && !(codePoint >= 0xd800 && codePoint <= 0xdfff)) {
        out += String.fromCodePoint(codePoint)
      } else {
        out += '\uFFFD'
      }
      i += 1 + hexMatch[0].length
      continue
    }
    if (input[i + 1] === '\n') {
      i += 2
      continue
    }
    out += input[i + 1]
    i += 2
  }
  return out
}

function normalizeSelector(raw: string): string {
  return raw
    .replace(/\s+/g, ' ')
    .replace(/\s*,\s*/g, ', ')
    .trim()
}

function combineNestedSelector(parentSel: string, childSel: string): string {
  const parents = parentSel.split(',').map(s => s.trim()).filter(Boolean)
  const children = childSel.split(',').map(s => s.trim()).filter(Boolean)
  const combined: string[] = []
  for (const p of parents) {
    for (const c of children) {
      if (c.includes('&')) {
        combined.push(c.replace(/&/g, p))
      } else {
        combined.push(`${p} ${c}`)
      }
    }
  }
  return normalizeSelector(combined.join(', '))
}

function parseDeclarationText(raw: string): CSSDeclaration | null {
  const cleaned = stripCSSComments(raw).trim()
  if (!cleaned) return null
  let parenDepth = 0
  let inQuote: string | null = null
  let colonIdx = -1
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i]
    if (inQuote) {
      if (ch === '\\' && i + 1 < cleaned.length) { i++; continue }
      if (ch === inQuote) inQuote = null
      continue
    }
    if (ch === '\'' || ch === '"') { inQuote = ch; continue }
    if (ch === '\\' && i + 1 < cleaned.length) { i++; continue }
    if (ch === '(') { parenDepth++; continue }
    if (ch === ')') { parenDepth = Math.max(0, parenDepth - 1); continue }
    if (ch === ':' && parenDepth === 0) {
      colonIdx = i
      break
    }
  }
  if (colonIdx <= 0) return null
  const propRaw = cleaned.slice(0, colonIdx).trim()
  const value = cleaned.slice(colonIdx + 1).trim()
  if (!propRaw || !value) return null
  // Custom properties are case-sensitive in CSS; standard properties are ASCII-lowercased.
  const property = propRaw.startsWith('--') ? propRaw : propRaw.toLowerCase()
  if (!/^(?:--[a-zA-Z0-9_-]+|-?[a-z][a-z0-9-]*)$/.test(property)) return null
  return { property, value }
}

function isRootSelector(selector: string): boolean {
  const parts = selector.split(',').map(s => s.trim().toLowerCase())
  return parts.some(p => p === ':root' || p === 'html')
}

type ParserFrame =
  | { kind: 'at-group'; header: string; nonSynth: boolean }
  | { kind: 'at-decl'; header: string; atRule: string; nonSynth: boolean; decls: CSSDeclaration[] }
  | { kind: 'rule'; selector: string; atRule: string; nonSynth: boolean; decls: CSSDeclaration[] }

export function parseCSSRules(css: string): CSSParseResult {
  const rootVars: Record<string, string> = {}
  if (!css) return { rules: [], rootVars }

  const norm = css.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const stack: ParserFrame[] = []
  const ruleOrder: string[] = []
  const mergedRules = new Map<string, { atRule: string; selector: string; synthesizable: boolean; declMap: Map<string, string> }>()

  const getAtRuleContext = (): string => {
    const parts: string[] = []
    for (const f of stack) {
      if (f.kind === 'at-group') parts.push(f.header)
    }
    return parts.join(' > ')
  }

  const isStackNonSynth = (): boolean => stack.some(f => f.nonSynth)

  const recordRule = (atRule: string, selector: string, synthesizable: boolean, decls: CSSDeclaration[]) => {
    if (decls.length === 0) return
    const normSel = normalizeSelector(selector)
    if (!normSel) return
    const key = `${atRule}\0${normSel}`
    let entry = mergedRules.get(key)
    if (!entry) {
      entry = { atRule, selector: normSel, synthesizable, declMap: new Map<string, string>() }
      mergedRules.set(key, entry)
      ruleOrder.push(key)
    }
    for (const d of decls) {
      entry.declMap.set(d.property, d.value)
    }
    if (isRootSelector(normSel) && (!atRule || /^@layer\b/i.test(atRule))) {
      for (const d of decls) {
        if (d.property.startsWith('--')) {
          rootVars[d.property] = d.value
        }
      }
    }
  }

  const flushFrame = (frame: ParserFrame) => {
    if (frame.kind === 'rule') {
      recordRule(frame.atRule, frame.selector, !frame.nonSynth, frame.decls)
    } else if (frame.kind === 'at-decl') {
      const ctx = frame.atRule ? `${frame.atRule} > ${frame.header}` : frame.header
      recordRule(ctx, frame.header, false, frame.decls)
    }
  }

  let buf = ''
  let parenDepth = 0
  let inQuote: string | null = null
  const len = norm.length
  let i = 0

  while (i < len) {
    const ch = norm[i]

    if (inQuote) {
      buf += ch
      if (ch === '\\' && i + 1 < len) {
        buf += norm[i + 1]
        i += 2
        continue
      }
      if (ch === inQuote) inQuote = null
      i++
      continue
    }

    // Skip /* ... */ comments (gracefully ends at EOF)
    if (ch === '/' && i + 1 < len && norm[i + 1] === '*') {
      i += 2
      while (i < len) {
        if (norm[i] === '*' && i + 1 < len && norm[i + 1] === '/') {
          i += 2
          break
        }
        i++
      }
      buf += ' '
      continue
    }

    if (ch === '\'' || ch === '"') {
      inQuote = ch
      buf += ch
      i++
      continue
    }

    if (ch === '\\' && i + 1 < len) {
      buf += ch + norm[i + 1]
      i += 2
      continue
    }

    if (ch === '(') {
      parenDepth++
      buf += ch
      i++
      continue
    }

    if (ch === ')') {
      parenDepth = Math.max(0, parenDepth - 1)
      buf += ch
      i++
      continue
    }

    if (parenDepth === 0 && ch === ';') {
      const top = stack[stack.length - 1]
      if (top && (top.kind === 'rule' || top.kind === 'at-decl')) {
        const decl = parseDeclarationText(buf)
        if (decl) top.decls.push(decl)
      }
      buf = ''
      i++
      continue
    }

    if (parenDepth === 0 && ch === '{') {
      const header = normalizeSelector(buf)
      buf = ''
      if (header.startsWith('@')) {
        const nameMatch = /^@([a-zA-Z_-][a-zA-Z0-9_-]*)/.exec(header)
        const atName = nameMatch ? nameMatch[1].toLowerCase() : ''
        if (hasOwn(GROUPING_AT_RULES, atName)) {
          stack.push({ kind: 'at-group', header, nonSynth: isStackNonSynth() })
        } else if (hasOwn(KEYFRAME_AT_RULES, atName)) {
          stack.push({ kind: 'at-group', header, nonSynth: true })
        } else if (hasOwn(DECLARATION_AT_RULES, atName)) {
          stack.push({ kind: 'at-decl', header, atRule: getAtRuleContext(), nonSynth: true, decls: [] })
        } else {
          stack.push({ kind: 'at-group', header, nonSynth: true })
        }
      } else {
        const parentRule = [...stack].reverse().find(f => f.kind === 'rule')
        const resolvedSelector = parentRule && parentRule.kind === 'rule'
          ? combineNestedSelector(parentRule.selector, header)
          : header
        stack.push({
          kind: 'rule',
          selector: resolvedSelector,
          atRule: getAtRuleContext(),
          nonSynth: isStackNonSynth(),
          decls: [],
        })
      }
      i++
      continue
    }

    if (parenDepth === 0 && ch === '}') {
      const top = stack.pop()
      if (top) {
        if ((top.kind === 'rule' || top.kind === 'at-decl') && buf.trim()) {
          const decl = parseDeclarationText(buf)
          if (decl) top.decls.push(decl)
        }
        flushFrame(top)
      }
      buf = ''
      i++
      continue
    }

    buf += ch
    i++
  }

  // Graceful EOF flush for 256 KB truncated stylesheets
  if (buf.trim() && stack.length > 0) {
    const top = stack[stack.length - 1]
    if (top.kind === 'rule' || top.kind === 'at-decl') {
      const decl = parseDeclarationText(buf)
      if (decl) top.decls.push(decl)
    }
  }
  while (stack.length > 0) {
    const frame = stack.pop()!
    flushFrame(frame)
  }

  const rules: CSSParsedRule[] = ruleOrder.map(key => {
    const entry = mergedRules.get(key)!
    const declarations: CSSDeclaration[] = []
    for (const [property, value] of entry.declMap.entries()) {
      declarations.push({ property, value })
    }
    return {
      atRule: entry.atRule,
      selector: entry.selector,
      synthesizable: entry.synthesizable,
      declarations,
    }
  })

  return { rules, rootVars }
}

// ── Strict Allowlist-Only Main-DOM Styling Helpers ─────────────────────────

const UNSAFE_CSS_FN_RE = /(?:^|[^a-z0-9_-])(?:url|image-set|-webkit-image-set|cross-fade|src|expression|behavior|-moz-binding)\s*\(/i

export function hasUnsafeCSSValue(val: string): boolean {
  if (!val) return false
  const clean = stripCSSComments(val)
  if (clean.includes('\\')) return true
  if (UNSAFE_CSS_FN_RE.test(clean)) return true
  if (/<\s*\/?\s*style|javascript\s*:/i.test(clean)) return true
  return false
}

function stripImportant(val: string): string {
  return stripCSSComments(val).replace(/\s*!important\s*$/i, '').trim()
}

// Single-hop var(--name[, fallback]) substitution (never recursive).
function resolveSingleHopVars(rawValue: string, rootVars: Record<string, string>): string {
  const clean = stripImportant(rawValue)
  if (!clean.includes('var(')) return clean
  return clean.replace(
    /var\(\s*(--[a-zA-Z0-9_-]+)\s*(?:,\s*([^()]+))?\s*\)/g,
    (_full, name: string, fallback?: string) => {
      if (hasOwn(rootVars, name)) {
        return stripImportant(rootVars[name])
      }
      return fallback ? fallback.trim() : _full
    },
  )
}

export function isColorBearingProperty(prop: string): boolean {
  const p = prop.toLowerCase()
  if (p.startsWith('--')) return true
  if (p === 'color') return true
  if (p.startsWith('background')) return true
  if (p.startsWith('border')) return true
  if (p.startsWith('outline')) return true
  if (p === 'fill' || p === 'stroke') return true
  if (
    p === 'accent-color' ||
    p === 'caret-color' ||
    p === 'text-decoration-color' ||
    p === 'column-rule-color' ||
    p === 'stop-color' ||
    p === 'flood-color' ||
    p === 'lighting-color' ||
    p === 'box-shadow' ||
    p === 'text-shadow'
  ) {
    return true
  }
  return false
}

const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/
const RGB_COMMA_RE = /^rgba?\(\s*(?:\d+(?:\.\d+)?%?)\s*,\s*(?:\d+(?:\.\d+)?%?)\s*,\s*(?:\d+(?:\.\d+)?%?)(?:\s*,\s*(?:\d*(?:\.\d+)?%?))?\s*\)$/i
const RGB_SPACE_RE = /^rgba?\(\s*(?:\d+(?:\.\d+)?%?|none)\s+(?:\d+(?:\.\d+)?%?|none)\s+(?:\d+(?:\.\d+)?%?|none)(?:\s*\/\s*(?:\d*(?:\.\d+)?%?|none))?\s*\)$/i
const HSL_COMMA_RE = /^hsla?\(\s*(?:[+-]?\d+(?:\.\d+)?(?:deg|rad|grad|turn)?)\s*,\s*(?:\d+(?:\.\d+)?%)\s*,\s*(?:\d+(?:\.\d+)?%)(?:\s*,\s*(?:\d*(?:\.\d+)?%?))?\s*\)$/i
const HSL_SPACE_RE = /^hsla?\(\s*(?:[+-]?\d+(?:\.\d+)?(?:deg|rad|grad|turn)?|none)\s+(?:\d+(?:\.\d+)?%?|none)\s+(?:\d+(?:\.\d+)?%?|none)(?:\s*\/\s*(?:\d*(?:\.\d+)?%?|none))?\s*\)$/i
const LCH_RE = /^ok?lch\(\s*(?:[+-]?\d*(?:\.\d+)?%?|none)\s+(?:[+-]?\d*(?:\.\d+)?%?|none)\s+(?:[+-]?\d*(?:\.\d+)?(?:deg|rad|grad|turn)?|none)(?:\s*\/\s*(?:\d*(?:\.\d+)?%?|none))?\s*\)$/i
const LAB_RE = /^ok?lab\(\s*(?:[+-]?\d*(?:\.\d+)?%?|none)\s+(?:[+-]?\d*(?:\.\d+)?%?|none)\s+(?:[+-]?\d*(?:\.\d+)?%?|none)(?:\s*\/\s*(?:\d*(?:\.\d+)?%?|none))?\s*\)$/i

function parseStrictColorToken(token: string, allowNamed: boolean): string | null {
  const t = token.trim()
  if (!t || hasUnsafeCSSValue(t)) return null
  if (HEX_COLOR_RE.test(t)) return t
  if (RGB_COMMA_RE.test(t) || RGB_SPACE_RE.test(t)) return t
  if (HSL_COMMA_RE.test(t) || HSL_SPACE_RE.test(t)) return t
  if (LCH_RE.test(t) || LAB_RE.test(t)) return t
  if (allowNamed) {
    const lower = t.toLowerCase()
    if (hasOwn(CSS_NAMED_COLORS, lower)) return lower
  }
  return null
}

function splitTopLevelTokens(val: string): string[] {
  const tokens: string[] = []
  let cur = ''
  let depth = 0
  for (let i = 0; i < val.length; i++) {
    const ch = val[i]
    if (ch === '(') { depth++; cur += ch; continue }
    if (ch === ')') { depth = Math.max(0, depth - 1); cur += ch; continue }
    if (depth === 0 && (ch === ' ' || ch === '\t' || ch === '\n')) {
      if (cur) { tokens.push(cur); cur = '' }
      continue
    }
    cur += ch
  }
  if (cur) tokens.push(cur)
  return tokens
}

function splitTopLevelCommas(val: string): string[] {
  const parts: string[] = []
  let cur = ''
  let depth = 0
  for (let i = 0; i < val.length; i++) {
    const ch = val[i]
    if (ch === '(') { depth++; cur += ch; continue }
    if (ch === ')') { depth = Math.max(0, depth - 1); cur += ch; continue }
    if (depth === 0 && ch === ',') {
      parts.push(cur.trim())
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur.trim()) parts.push(cur.trim())
  return parts
}

const SHORTHAND_COLOR_PROPS: Record<string, true> = {
  background: true,
  border: true,
  'border-top': true,
  'border-right': true,
  'border-bottom': true,
  'border-left': true,
  outline: true,
  'box-shadow': true,
  'text-shadow': true,
}

export function extractSafeColor(
  prop: string,
  rawValue: string,
  rootVars: Record<string, string> = {},
): string | null {
  if (!isColorBearingProperty(prop)) return null
  if (hasUnsafeCSSValue(rawValue)) return null
  const resolved = resolveSingleHopVars(rawValue, rootVars)
  if (!resolved || hasUnsafeCSSValue(resolved)) return null

  const exact = parseStrictColorToken(resolved, true)
  if (exact) return exact

  const p = prop.toLowerCase()
  if (hasOwn(SHORTHAND_COLOR_PROPS, p)) {
    const tokens = splitTopLevelTokens(resolved)
    for (const tok of tokens) {
      const c = parseStrictColorToken(tok, true)
      if (c) return c
    }
  }
  return null
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n))
}

function parsePxLength(token: string): number | null {
  const m = /^([+-]?\d+(?:\.\d+)?)(px|rem|em)?$/i.exec(token.trim())
  if (!m) return null
  const num = Number(m[1])
  if (!Number.isFinite(num)) return null
  const unit = (m[2] || '').toLowerCase()
  if (!unit && num !== 0) return null
  if (unit === 'rem' || unit === 'em') return num * 16
  return num
}

const GRADIENT_DIR_RE = /^(?:to\s+(?:top|bottom|left|right)(?:\s+(?:top|bottom|left|right))?|[+-]?\d+(?:\.\d+)?(?:deg|rad|grad|turn)|circle|ellipse)$/i

function parseSafeGradient(resolved: string): string | null {
  const m = /^(linear-gradient|radial-gradient)\((.+)\)$/i.exec(resolved.trim())
  if (!m) return null
  const fnName = m[1].toLowerCase()
  const args = splitTopLevelCommas(m[2])
  if (args.length < 2) return null

  const validated: string[] = []
  let startIdx = 0
  if (GRADIENT_DIR_RE.test(args[0])) {
    validated.push(args[0].toLowerCase().replace(/\s+/g, ' '))
    startIdx = 1
  }
  if (args.length - startIdx < 2) return null

  for (let i = startIdx; i < args.length; i++) {
    const tokens = splitTopLevelTokens(args[i])
    if (tokens.length === 0 || tokens.length > 2) return null
    const color = parseStrictColorToken(tokens[0], true)
    if (!color) return null
    if (tokens.length === 2) {
      if (!/^\d+(?:\.\d+)?(?:%|px)$/i.test(tokens[1])) return null
      validated.push(`${color} ${tokens[1]}`)
    } else {
      validated.push(color)
    }
  }
  return `${fnName}(${validated.join(', ')})`
}

function parseSafeBoxShadow(resolved: string): string | null {
  const lower = resolved.trim().toLowerCase()
  if (lower === 'none') return 'none'
  // Take first shadow if comma-separated so preview remains bounded and clean
  const first = splitTopLevelCommas(resolved)[0]
  if (!first) return null
  const tokens = splitTopLevelTokens(first)
  let inset = false
  const lengths: number[] = []
  let color: string | null = null

  for (const tok of tokens) {
    if (tok.toLowerCase() === 'inset') {
      inset = true
      continue
    }
    const px = parsePxLength(tok)
    if (px !== null) {
      lengths.push(px)
      continue
    }
    const c = parseStrictColorToken(tok, true)
    if (c && !color) {
      color = c
      continue
    }
    return null
  }
  if (lengths.length < 2 || lengths.length > 4) return null
  const x = Math.round(clamp(lengths[0], -16, 16))
  const y = Math.round(clamp(lengths[1], -16, 16))
  const blur = lengths.length >= 3 ? Math.round(clamp(lengths[2], 0, 24)) : 0
  const spread = lengths.length === 4 ? Math.round(clamp(lengths[3], -8, 8)) : 0
  const safeColor = color || 'rgba(0, 0, 0, 0.35)'
  const parts = [
    ...(inset ? ['inset'] : []),
    `${x}px`,
    `${y}px`,
    `${blur}px`,
    ...(lengths.length === 4 ? [`${spread}px`] : []),
    safeColor,
  ]
  return parts.join(' ')
}

export function extractSafeVisualTile(
  prop: string,
  rawValue: string,
  rootVars: Record<string, string> = {},
): SafeVisualTile | null {
  if (hasUnsafeCSSValue(rawValue)) return null
  const resolved = resolveSingleHopVars(rawValue, rootVars)
  if (!resolved || hasUnsafeCSSValue(resolved)) return null
  const p = prop.toLowerCase()

  if (p === 'font-size') {
    const px = parsePxLength(resolved)
    if (px === null) return null
    return { kind: 'font-size', px: Math.round(clamp(px, 10, 36)) }
  }

  if (p === 'font-weight') {
    const lower = resolved.toLowerCase()
    if (lower === 'normal') return { kind: 'font-weight', weight: 400 }
    if (lower === 'bold') return { kind: 'font-weight', weight: 700 }
    if (/^\d{3}$/.test(lower)) {
      const w = Number(lower)
      if (w >= 100 && w <= 900) return { kind: 'font-weight', weight: w }
    }
    return null
  }

  if (p === 'border-radius') {
    const first = splitTopLevelTokens(resolved)[0]
    if (!first) return null
    if (/^\d+(?:\.\d+)?%$/.test(first)) {
      const pct = Number(first.slice(0, -1))
      if (!Number.isFinite(pct)) return null
      return { kind: 'border-radius', px: Math.round(clamp((pct / 50) * 32, 0, 32)) }
    }
    const px = parsePxLength(first)
    if (px === null) return null
    return { kind: 'border-radius', px: Math.round(clamp(px, 0, 32)) }
  }

  if (p === 'opacity') {
    if (/^\d+(?:\.\d+)?%$/.test(resolved)) {
      const pct = Number(resolved.slice(0, -1))
      if (!Number.isFinite(pct)) return null
      return { kind: 'opacity', value: clamp(pct / 100, 0, 1) }
    }
    if (/^(?:0?\.\d+|1(?:\.0+)?|0)$/.test(resolved)) {
      return { kind: 'opacity', value: clamp(Number(resolved), 0, 1) }
    }
    return null
  }

  if (
    p === 'border' ||
    p === 'border-top' ||
    p === 'border-right' ||
    p === 'border-bottom' ||
    p === 'border-left' ||
    p === 'outline'
  ) {
    const tokens = splitTopLevelTokens(resolved)
    let widthPx: number | null = null
    let style: 'solid' | 'dashed' | 'dotted' | 'double' | null = null
    let color: string | null = null
    for (const tok of tokens) {
      const lower = tok.toLowerCase()
      if (hasOwn(BORDER_STYLES, lower) && !style) {
        style = BORDER_STYLES[lower]
        continue
      }
      const px = parsePxLength(tok)
      if (px !== null && widthPx === null) {
        widthPx = Math.round(clamp(px, 1, 6))
        continue
      }
      const c = parseStrictColorToken(tok, true)
      if (c && !color) {
        color = c
        continue
      }
    }
    if (!style) return null
    return {
      kind: 'border',
      widthPx: widthPx ?? 1,
      style,
      color: color ?? '#8b7cff',
    }
  }

  if (p === 'box-shadow') {
    const shadow = parseSafeBoxShadow(resolved)
    return shadow ? { kind: 'box-shadow', shadow } : null
  }

  if (p === 'background' || p === 'background-image') {
    const color = parseStrictColorToken(resolved, true)
    if (color) return { kind: 'color', color }
    const gradient = parseSafeGradient(resolved)
    if (gradient) return { kind: 'gradient', gradient }
    return null
  }

  if (isColorBearingProperty(p)) {
    const color = extractSafeColor(p, rawValue, rootVars)
    if (color) return { kind: 'color', color }
  }

  return null
}

// ── Visual CSS Diff Engine ─────────────────────────────────────────────────

export function diffCSSVisual(oldCSS: string, newCSS: string): CSSVisualDiff {
  const oldParsed = parseCSSRules(oldCSS)
  const newParsed = parseCSSRules(newCSS)

  const oldMap = new Map<string, CSSParsedRule>()
  const newMap = new Map<string, CSSParsedRule>()
  const allKeys: string[] = []
  const seenKeys = new Set<string>()

  for (const r of newParsed.rules) {
    const key = `${r.atRule}\0${r.selector}`
    newMap.set(key, r)
    if (!seenKeys.has(key)) { seenKeys.add(key); allKeys.push(key) }
  }
  for (const r of oldParsed.rules) {
    const key = `${r.atRule}\0${r.selector}`
    oldMap.set(key, r)
    if (!seenKeys.has(key)) { seenKeys.add(key); allKeys.push(key) }
  }

  const colorChanges: CSSColorChange[] = []
  const tokenChanges: CSSTokenChange[] = []
  const selectorDiffs: CSSSelectorDiff[] = []
  const changedSelectorsSet = new Set<string>()

  for (const key of allKeys) {
    const oldRule = oldMap.get(key)
    const newRule = newMap.get(key)
    const atRule = newRule?.atRule ?? oldRule?.atRule ?? ''
    const selector = newRule?.selector ?? oldRule?.selector ?? ''
    const synthesizable = newRule?.synthesizable ?? oldRule?.synthesizable ?? false

    const oldDecls = new Map<string, string>()
    const newDecls = new Map<string, string>()
    const propOrder: string[] = []
    const seenProps = new Set<string>()

    if (newRule) {
      for (const d of newRule.declarations) {
        newDecls.set(d.property, d.value)
        if (!seenProps.has(d.property)) { seenProps.add(d.property); propOrder.push(d.property) }
      }
    }
    if (oldRule) {
      for (const d of oldRule.declarations) {
        oldDecls.set(d.property, d.value)
        if (!seenProps.has(d.property)) { seenProps.add(d.property); propOrder.push(d.property) }
      }
    }

    const declDiffs: CSSSelectorDeclDiff[] = []

    for (const prop of propOrder) {
      const oldVal = oldDecls.has(prop) ? oldDecls.get(prop)! : null
      const newVal = newDecls.has(prop) ? newDecls.get(prop)! : null
      if (oldVal === newVal) continue

      const status: CSSDeclChangeStatus =
        oldVal === null ? 'added' : newVal === null ? 'removed' : 'changed'

      const oldTile = oldVal !== null ? extractSafeVisualTile(prop, oldVal, oldParsed.rootVars) : null
      const newTile = newVal !== null ? extractSafeVisualTile(prop, newVal, newParsed.rootVars) : null
      const oldColor = oldVal !== null ? extractSafeColor(prop, oldVal, oldParsed.rootVars) : null
      const newColor = newVal !== null ? extractSafeColor(prop, newVal, newParsed.rootVars) : null

      declDiffs.push({
        property: prop,
        status,
        oldRaw: oldVal,
        newRaw: newVal,
        oldTile,
        newTile,
      })

      if (prop.startsWith('--')) {
        tokenChanges.push({
          name: prop,
          selector,
          atRule,
          status,
          oldRaw: oldVal,
          newRaw: newVal,
          oldColor,
          newColor,
        })
      } else if (oldColor || newColor) {
        colorChanges.push({
          id: `${atRule}|${selector}|${prop}`,
          selector,
          atRule,
          property: prop,
          status,
          oldRaw: oldVal,
          newRaw: newVal,
          oldColor,
          newColor,
        })
      }
    }

    if (declDiffs.length > 0) {
      selectorDiffs.push({
        atRule,
        selector,
        synthesizable,
        declarations: declDiffs,
      })
      if (synthesizable) {
        changedSelectorsSet.add(selector)
      }
    }
  }

  return {
    colorChanges,
    tokenChanges,
    selectorDiffs,
    changedSelectors: Array.from(changedSelectorsSet),
    hasVisualDiffs: selectorDiffs.length > 0 || colorChanges.length > 0 || tokenChanges.length > 0,
  }
}

// ── Hardened Sandboxed Preview Sanitizer & Document Builder ────────────────

const FORBIDDEN_PREVIEW_FN_RE = /(?:url|image-set|-webkit-image-set|cross-fade|src|expression|behavior|-moz-binding)\s*\(/i

function hasForbiddenPreviewFunction(segment: string): boolean {
  const decoded = decodeCSSEscapes(segment)
  return FORBIDDEN_PREVIEW_FN_RE.test(decoded) || FORBIDDEN_PREVIEW_FN_RE.test(segment)
}

function getDecodedAtRuleName(raw: string): string | null {
  const trimmed = raw.trimStart()
  if (!trimmed.startsWith('@')) return null
  const decoded = decodeCSSEscapes(trimmed)
  const m = /^@([a-zA-Z_-][a-zA-Z0-9_-]*)/.exec(decoded)
  return m ? m[1].toLowerCase() : ''
}

export function sanitizeCSSForPreview(css: string): string {
  if (!css) return ''
  // Step 1: Strip all /* ... */ comments (including unclosed trailing comments).
  const noComments = stripCSSComments(css)

  // Step 2: Stream through statements/blocks removing @import, @font-face, and
  // any declaration whose decoded form invokes url(/image-set(/cross-fade(/src(/expression(.
  const out: string[] = []
  let buf = ''
  let parenDepth = 0
  let inQuote: string | null = null
  let skipBlockDepth = 0
  let skipUntilSemicolon = false
  const len = noComments.length
  let i = 0

  const flushDeclBuffer = (terminator: string) => {
    const trimmed = buf.trim()
    if (trimmed) {
      const atName = getDecodedAtRuleName(trimmed)
      if (atName === 'import') {
        // Drop @import statement
      } else if (!hasForbiddenPreviewFunction(trimmed)) {
        out.push(buf, terminator)
      }
    } else if (terminator === '}') {
      out.push(terminator)
    }
    buf = ''
  }

  while (i < len) {
    const ch = noComments[i]

    if (skipUntilSemicolon) {
      if (inQuote) {
        if (ch === '\\' && i + 1 < len) { i += 2; continue }
        if (ch === inQuote) inQuote = null
        i++
        continue
      }
      if (ch === '\'' || ch === '"') { inQuote = ch; i++; continue }
      if (ch === ';') { skipUntilSemicolon = false; i++; continue }
      if (ch === '}') { skipUntilSemicolon = false; out.push('}'); i++; continue }
      i++
      continue
    }

    if (skipBlockDepth > 0) {
      if (inQuote) {
        if (ch === '\\' && i + 1 < len) { i += 2; continue }
        if (ch === inQuote) inQuote = null
        i++
        continue
      }
      if (ch === '\'' || ch === '"') { inQuote = ch; i++; continue }
      if (ch === '{') skipBlockDepth++
      else if (ch === '}') skipBlockDepth--
      i++
      continue
    }

    if (inQuote) {
      buf += ch
      if (ch === '\\' && i + 1 < len) {
        buf += noComments[i + 1]
        i += 2
        continue
      }
      if (ch === inQuote) inQuote = null
      i++
      continue
    }

    if (ch === '\'' || ch === '"') {
      inQuote = ch
      buf += ch
      i++
      continue
    }

    if (ch === '\\' && i + 1 < len) {
      buf += ch + noComments[i + 1]
      i += 2
      continue
    }

    if (ch === '(') {
      parenDepth++
      buf += ch
      i++
      continue
    }

    if (ch === ')') {
      parenDepth = Math.max(0, parenDepth - 1)
      buf += ch
      i++
      continue
    }

    if (parenDepth === 0 && ch === ';') {
      flushDeclBuffer(';')
      i++
      continue
    }

    if (parenDepth === 0 && ch === '{') {
      const atName = getDecodedAtRuleName(buf)
      if (atName === 'font-face' || atName === 'import') {
        buf = ''
        skipBlockDepth = 1
      } else if (hasForbiddenPreviewFunction(buf)) {
        buf = ''
        skipBlockDepth = 1
      } else {
        out.push(buf, '{')
        buf = ''
      }
      i++
      continue
    }

    if (parenDepth === 0 && ch === '}') {
      const trimmed = buf.trim()
      if (trimmed && !hasForbiddenPreviewFunction(trimmed) && getDecodedAtRuleName(trimmed) !== 'import') {
        out.push(buf)
      }
      buf = ''
      out.push('}')
      i++
      continue
    }

    // Catch `@import` even when trailing text lacks `;` before EOF
    if (parenDepth === 0 && ch === '@' && buf.trim() === '') {
      const ahead = noComments.slice(i, i + 40)
      const atName = getDecodedAtRuleName(ahead)
      if (atName === 'import') {
        skipUntilSemicolon = true
        i++
        continue
      }
    }

    buf += ch
    i++
  }

  if (buf.trim() && !skipBlockDepth && !skipUntilSemicolon) {
    const atName = getDecodedAtRuleName(buf)
    if (atName !== 'import' && atName !== 'font-face' && !hasForbiddenPreviewFunction(buf)) {
      out.push(buf)
    }
  }

  // Step 3: Unconditionally escape every `</` sequence so no case/whitespace
  // variant (`</STYLE>`, `</style\t/>`) can break out of HTML5 RAWTEXT `<style>`.
  return out.join('').replace(/<\//g, '<\\/')
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const SAFE_CLASS_TOKEN_RE = /^[a-zA-Z0-9_:/.-]+$/
const SAFE_ID_TOKEN_RE = /^[a-zA-Z0-9_-]+$/

interface SpecimenNode {
  tag: string
  id: string | null
  classes: string[]
  label: string
}

function parseSingleSynthesizableSelector(rawSelector: string): SpecimenNode | null {
  if (!rawSelector) return null
  // Reject any HTML/attribute metacharacters or attribute selectors `[...]`
  if (/[<>"'\r\n[\]]/.test(rawSelector)) return null

  // Extract rightmost compound selector after combinators (space, >, +, ~)
  const segments = rawSelector.trim().split(/[\s>+~]+/).filter(Boolean)
  if (segments.length === 0) return null
  const last = segments[segments.length - 1]
  if (!last || last === '*' || last.startsWith(':') || last.startsWith('@')) return null

  // Walk the compound selector respecting CSS `\` escapes; stop at unescaped `:` (pseudo-class/element)
  let tagPart = ''
  let idPart: string | null = null
  const classes: string[] = []
  let mode: 'tag' | 'id' | 'class' = 'tag'
  let cur = ''

  const commit = () => {
    if (!cur) return
    if (mode === 'tag') {
      tagPart = cur.toLowerCase()
    } else if (mode === 'id') {
      idPart = cur
    } else {
      classes.push(cur)
    }
    cur = ''
  }

  for (let i = 0; i < last.length; i++) {
    const ch = last[i]
    if (ch === '\\') {
      if (i + 1 < last.length) {
        // Consume hex escape or single char escape
        const hexMatch = /^[0-9a-fA-F]{1,6}[ \t]?/.exec(last.slice(i + 1))
        if (hexMatch) {
          cur += decodeCSSEscapes('\\' + hexMatch[0])
          i += hexMatch[0].length
        } else {
          cur += last[i + 1]
          i++
        }
      }
      continue
    }
    if (ch === ':') {
      // Pseudo-class or pseudo-element — stop parsing base compound
      break
    }
    if (ch === '.') {
      commit()
      mode = 'class'
      continue
    }
    if (ch === '#') {
      commit()
      mode = 'id'
      continue
    }
    cur += ch
  }
  commit()

  // Validate tag against strict allowlist
  const tag = tagPart || 'div'
  if (!hasOwn(ALLOWED_SPECIMEN_TAGS, tag)) return null

  // Validate id & classes strictly
  if (idPart !== null && !SAFE_ID_TOKEN_RE.test(idPart)) return null
  for (const cls of classes) {
    if (!SAFE_CLASS_TOKEN_RE.test(cls)) return null
  }
  if (!idPart && classes.length === 0 && !tagPart) return null

  return {
    tag,
    id: idPart,
    classes,
    label: rawSelector.trim(),
  }
}

export function synthesizeSpecimenHTML(changedSelectors: string[]): string {
  const nodes: SpecimenNode[] = []
  const seen = new Set<string>()

  for (const selGroup of changedSelectors) {
    if (nodes.length >= MAX_SYNTHESIZED_NODES) break
    const parts = selGroup.split(',')
    for (const part of parts) {
      if (nodes.length >= MAX_SYNTHESIZED_NODES) break
      const spec = parseSingleSynthesizableSelector(part)
      if (!spec) continue
      const key = `${spec.tag}#${spec.id ?? ''}.${spec.classes.join('.')}`
      if (seen.has(key)) continue
      seen.add(key)
      nodes.push(spec)
    }
  }

  if (nodes.length === 0) return ''

  const rendered = nodes.map(node => {
    const attrs: string[] = []
    if (node.id) attrs.push(`id="${escapeHTML(node.id)}"`)
    if (node.classes.length > 0) attrs.push(`class="${escapeHTML(node.classes.join(' '))}"`)
    const attrStr = attrs.length > 0 ? ' ' + attrs.join(' ') : ''
    const label = escapeHTML(node.label)

    if (node.tag === 'input') {
      return `<div class="__rc-item"><div class="__rc-sel">${label}</div><input type="text"${attrStr} value="Sample input" readonly /></div>`
    }
    if (node.tag === 'a') {
      return `<div class="__rc-item"><div class="__rc-sel">${label}</div><a${attrStr}>Sample link</a></div>`
    }
    if (node.tag === 'li') {
      return `<div class="__rc-item"><div class="__rc-sel">${label}</div><ul><li${attrStr}>Sample list item</li></ul></div>`
    }
    if (node.tag === 'tr') {
      return `<div class="__rc-item"><div class="__rc-sel">${label}</div><table><tbody><tr${attrStr}><td>Sample row</td></tr></tbody></table></div>`
    }
    if (node.tag === 'td' || node.tag === 'th') {
      return `<div class="__rc-item"><div class="__rc-sel">${label}</div><table><tbody><tr><${node.tag}${attrStr}>Sample cell</${node.tag}></tr></tbody></table></div>`
    }
    return `<div class="__rc-item"><div class="__rc-sel">${label}</div><${node.tag}${attrStr}>Sample ${escapeHTML(node.tag)} (${label})</${node.tag}></div>`
  })

  return `<section class="__rc-section"><div class="__rc-heading">Changed selectors (${nodes.length})</div><div class="__rc-grid">${rendered.join('')}</div></section>`
}

export function buildSandboxedPreviewDoc(
  css: string,
  changedSelectors: string[],
  canvasTheme: 'light' | 'dark',
): string {
  const safeCSS = sanitizeCSSForPreview(css)
  const synthHTML = synthesizeSpecimenHTML(changedSelectors)
  const bg = canvasTheme === 'light' ? '#ffffff' : '#101522'
  const fg = canvasTheme === 'light' ? '#111827' : '#f3f5fb'
  const muted = canvasTheme === 'light' ? '#6b7280' : '#94a3b8'
  const border = canvasTheme === 'light' ? '#e5e7eb' : '#222b3d'
  const cardBg = canvasTheme === 'light' ? '#f9fafb' : '#171d2c'

  return [
    '<!doctype html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
    '<style>',
    `html, body { margin: 0; padding: 0; background: ${bg}; color: ${fg}; font-family: system-ui, -apple-system, sans-serif; font-size: 13px; line-height: 1.5; }`,
    `.__rc-root { isolation: isolate; padding: 14px; display: flex; flex-direction: column; gap: 14px; }`,
    `.__rc-section { border: 1px solid ${border}; border-radius: 8px; padding: 10px 12px; background: ${cardBg}; }`,
    `.__rc-heading { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: ${muted}; margin-bottom: 8px; font-weight: 600; }`,
    `.__rc-grid { display: flex; flex-direction: column; gap: 8px; }`,
    `.__rc-item { border-top: 1px dashed ${border}; padding-top: 6px; }`,
    `.__rc-item:first-child { border-top: 0; padding-top: 0; }`,
    `.__rc-sel { font-family: ui-monospace, monospace; font-size: 10px; color: ${muted}; margin-bottom: 4px; }`,
    `.__rc-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 8px; }`,
    '</style>',
    '<style>',
    safeCSS,
    '</style>',
    '</head>',
    '<body>',
    '<div class="__rc-root">',
    synthHTML,
    '<section class="__rc-section">',
    '<div class="__rc-heading">Base specimen</div>',
    '<header><nav class="__rc-row"><a>Home</a><a>Docs</a><a>Settings</a></nav></header>',
    '<h1>Heading One</h1>',
    '<h2>Heading Two</h2>',
    '<p>Body copy paragraph with a <a>sample link</a> and <span class="badge">badge</span>.</p>',
    '<div class="__rc-row">',
    '<button type="button" class="btn btn-primary">Primary action</button>',
    '<button type="button" class="btn btn-secondary">Secondary</button>',
    '<input type="text" value="Text input" readonly />',
    '</div>',
    '<article class="card"><div class="card-body">Card specimen container</div></article>',
    '<table><thead><tr><th>Column A</th><th>Column B</th></tr></thead><tbody><tr><td>Value 1</td><td>Value 2</td></tr></tbody></table>',
    '</section>',
    '</div>',
    '</body>',
    '</html>',
  ].join('\n')
}
