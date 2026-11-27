import { diffLines } from 'diff'

export type DiffLineKind = 'context' | 'added' | 'removed'

export interface DiffLine {
  kind: DiffLineKind
  text: string
  oldLine: number | null
  newLine: number | null
}

export interface DiffContextBlock {
  kind: 'context'
  lines: DiffLine[]
}

export interface DiffChangeBlock {
  kind: 'change'
  changeIndex: number
  lines: DiffLine[]
}

export type DiffBlock = DiffContextBlock | DiffChangeBlock

export interface DiffResult {
  blocks: DiffBlock[]
  totalChanges: number
  addedLines: number
  removedLines: number
  simplified: boolean
}

export interface BeautifyResult {
  text: string
  lineCount: number
  exceededCap: boolean
}

export interface FoldedContext {
  collapsed: boolean
  top: DiffLine[]
  hidden: DiffLine[]
  bottom: DiffLine[]
}

export interface BuildDiffOptions {
  timeout?: number
  maxEditLength?: number
}

const DEFAULT_MAX_LINES = 12000
const DEFAULT_DIFF_TIMEOUT = 400
const DEFAULT_MAX_EDIT_LENGTH = 4000

export function normalizeNewlines(text: string): string {
  if (!text) return ''
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

function looksMinified(text: string): boolean {
  if (!text) return false
  const norm = normalizeNewlines(text)
  let maxLineLen = 0
  let lineCount = 1
  let curLen = 0
  for (let i = 0; i < norm.length; i++) {
    if (norm.charCodeAt(i) === 10) {
      if (curLen > maxLineLen) maxLineLen = curLen
      curLen = 0
      lineCount++
    } else {
      curLen++
    }
  }
  if (curLen > maxLineLen) maxLineLen = curLen
  if (maxLineLen > 500) return true
  if (norm.length > 1000 && norm.length / lineCount > 300) return true
  return false
}

export function shouldAutoBeautify(oldText: string, newText: string): boolean {
  return looksMinified(oldText) || looksMinified(newText)
}

const REGEX_PRECEDING_KEYWORDS: Record<string, true> = {
  return: true,
  case: true,
  throw: true,
  delete: true,
  void: true,
  typeof: true,
  in: true,
  instanceof: true,
  new: true,
  of: true,
  yield: true,
  await: true,
  else: true,
  do: true,
}

const CONTROL_PAREN_KEYWORDS: Record<string, true> = {
  if: true,
  while: true,
  with: true,
}
function isIdentStart(ch: string): boolean {
  const c = ch.charCodeAt(0)
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 36 || c > 127
}

function isIdentPart(ch: string): boolean {
  const c = ch.charCodeAt(0)
  return isIdentStart(ch) || (c >= 48 && c <= 57)
}

function isDigit(ch: string): boolean {
  const c = ch.charCodeAt(0)
  return c >= 48 && c <= 57
}

function peekNextNonSpace(src: string, start: number): string {
  let i = start
  while (i < src.length) {
    const ch = src[i]
    if (ch !== ' ' && ch !== '\t' && ch !== '\n') return ch
    i++
  }
  return ''
}

function beautifyJS(norm: string, maxLines: number): BeautifyResult {
  const out: string[] = []
  let lineCount = 1
  let indent = 0
  let atLineStart = true

  // Token classification for `/` regex-vs-division disambiguation.
  // 'expr_start': `/` begins a regex literal.
  // 'expr_end': `/` is the division operator.
  let lastToken: 'expr_start' | 'expr_end' = 'expr_start'
  let lastWord = ''
  let prevWord = ''

  // Track paren kinds so `for (;;)` never splits `;` and `if (x) /re/` works.
  const parenStack: Array<'for' | 'control' | 'other'> = []
  let forParenDepth = 0

  // Template literal nesting: each entry is the `{` nesting depth inside `${ ... }`.
  const templateBraceStack: number[] = []
  let inTemplate = false

  const emitRaw = (s: string) => {
    out.push(s)
    atLineStart = false
  }

  const emitIndent = () => {
    if (indent > 0) out.push('  '.repeat(indent))
  }

  const emitNewline = (): boolean => {
    // Trim trailing horizontal spaces on the current line.
    while (out.length > 0) {
      const last = out[out.length - 1]
      if (last === ' ' || last === '\t') {
        out.pop()
      } else {
        break
      }
    }
    out.push('\n')
    lineCount++
    atLineStart = true
    return lineCount > maxLines
  }

  const ensureLineStart = () => {
    if (atLineStart) {
      emitIndent()
      atLineStart = false
    }
  }

  const len = norm.length
  let i = 0

  while (i < len) {
    if (lineCount > maxLines) {
      return { text: norm, lineCount, exceededCap: true }
    }

    if (inTemplate) {
      const ch = norm[i]
      if (ch === '\\') {
        if (i + 1 < len) {
          const next = norm[i + 1]
          emitRaw(ch + next)
          if (next === '\n') {
            lineCount++
            if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
          }
          i += 2
        } else {
          // Graceful EOF inside escape
          emitRaw(ch)
          i++
        }
        continue
      }
      if (ch === '$' && i + 1 < len && norm[i + 1] === '{') {
        emitRaw('${')
        templateBraceStack.push(0)
        inTemplate = false
        lastToken = 'expr_start'
        lastWord = ''
        i += 2
        continue
      }
      if (ch === '`') {
        emitRaw('`')
        inTemplate = false
        lastToken = 'expr_end'
        lastWord = ''
        i++
        continue
      }
      if (ch === '\n') {
        out.push('\n')
        lineCount++
        if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
        i++
        continue
      }
      emitRaw(ch)
      i++
      continue
    }

    const ch = norm[i]

    // Whitespace
    if (ch === ' ' || ch === '\t') {
      if (!atLineStart) {
        const last = out[out.length - 1]
        if (last && last !== ' ' && last !== '\t' && last !== '\n') {
          out.push(' ')
        }
      }
      i++
      continue
    }

    if (ch === '\n') {
      if (!atLineStart) {
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      }
      i++
      continue
    }

    // Single-line comment //
    if (ch === '/' && i + 1 < len && norm[i + 1] === '/') {
      ensureLineStart()
      let end = i + 2
      while (end < len && norm[end] !== '\n') end++
      emitRaw(norm.slice(i, end))
      i = end
      if (i < len && norm[i] === '\n') {
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
        i++
      }
      continue
    }

    // Block comment /* ... */
    if (ch === '/' && i + 1 < len && norm[i + 1] === '*') {
      ensureLineStart()
      let end = i + 2
      while (end < len) {
        if (norm[end] === '*' && end + 1 < len && norm[end + 1] === '/') {
          end += 2
          break
        }
        if (norm[end] === '\n') {
          lineCount++
          if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
        }
        end++
      }
      emitRaw(norm.slice(i, end))
      i = end
      continue
    }

    // String literals '...' or "..."
    if (ch === '\'' || ch === '"') {
      ensureLineStart()
      const quote = ch
      let end = i + 1
      while (end < len) {
        const c = norm[end]
        if (c === '\\') {
          if (end + 1 < len) {
            if (norm[end + 1] === '\n') {
              lineCount++
              if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
            }
            end += 2
          } else {
            end++
          }
          continue
        }
        if (c === quote) {
          end++
          break
        }
        if (c === '\n') {
          // Unterminated single-line string (or EOF truncation)
          break
        }
        end++
      }
      emitRaw(norm.slice(i, end))
      lastToken = 'expr_end'
      lastWord = ''
      i = end
      continue
    }

    // Template literal opening backtick
    if (ch === '`') {
      ensureLineStart()
      emitRaw('`')
      inTemplate = true
      lastWord = ''
      i++
      continue
    }

    // Regex literal vs division operator
    if (ch === '/') {
      ensureLineStart()
      if (lastToken === 'expr_start') {
        let end = i + 1
        let inCharClass = false
        let closed = false
        while (end < len) {
          const c = norm[end]
          if (c === '\\') {
            if (end + 1 < len && norm[end + 1] !== '\n') {
              end += 2
              continue
            }
            end++
            break
          }
          if (c === '\n') {
            break
          }
          if (c === '[' && !inCharClass) {
            inCharClass = true
            end++
            continue
          }
          if (c === ']' && inCharClass) {
            inCharClass = false
            end++
            continue
          }
          if (c === '/' && !inCharClass) {
            end++
            while (end < len && isIdentPart(norm[end])) end++
            closed = true
            break
          }
          end++
        }
        emitRaw(norm.slice(i, end))
        lastToken = closed ? 'expr_end' : 'expr_start'
        lastWord = ''
        i = end
        continue
      }
      // Division operator (or /=)
      if (i + 1 < len && norm[i + 1] === '=') {
        emitRaw('/=')
        i += 2
      } else {
        emitRaw('/')
        i++
      }
      lastToken = 'expr_start'
      lastWord = ''
      continue
    }

    // Identifier / keyword
    if (isIdentStart(ch)) {
      ensureLineStart()
      let end = i + 1
      while (end < len && isIdentPart(norm[end])) end++
      const word = norm.slice(i, end)
      emitRaw(word)
      prevWord = lastWord
      lastWord = word
      lastToken = Object.prototype.hasOwnProperty.call(REGEX_PRECEDING_KEYWORDS, word) ? 'expr_start' : 'expr_end'
      i = end
      continue
    }

    // Number literal
    if (isDigit(ch)) {
      ensureLineStart()
      let end = i + 1
      while (end < len) {
        const c = norm[end]
        if (isDigit(c) || isIdentPart(c) || c === '.') {
          end++
        } else if ((c === '+' || c === '-') && (norm[end - 1] === 'e' || norm[end - 1] === 'E')) {
          end++
        } else {
          break
        }
      }
      emitRaw(norm.slice(i, end))
      lastToken = 'expr_end'
      lastWord = ''
      i = end
      continue
    }

    // Braces
    if (ch === '{') {
      ensureLineStart()
      if (templateBraceStack.length > 0) {
        templateBraceStack[templateBraceStack.length - 1]++
        emitRaw('{')
        lastToken = 'expr_start'
        lastWord = ''
        i++
        continue
      }
      const next = peekNextNonSpace(norm, i + 1)
      if (next === '}') {
        // Keep empty `{}` compact
        emitRaw('{}')
        let j = i + 1
        while (j < len && norm[j] !== '}') j++
        i = j + 1
        lastToken = 'expr_start'
        lastWord = ''
        continue
      }
      emitRaw('{')
      indent++
      if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      lastToken = 'expr_start'
      lastWord = ''
      i++
      continue
    }

    if (ch === '}') {
      if (templateBraceStack.length > 0) {
        const top = templateBraceStack[templateBraceStack.length - 1]
        if (top === 0) {
          templateBraceStack.pop()
          emitRaw('}')
          inTemplate = true
          lastWord = ''
          i++
          continue
        }
        templateBraceStack[templateBraceStack.length - 1] = top - 1
        emitRaw('}')
        lastToken = 'expr_end'
        lastWord = ''
        i++
        continue
      }
      indent = Math.max(0, indent - 1)
      if (!atLineStart) {
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      }
      ensureLineStart()
      emitRaw('}')
      const next = peekNextNonSpace(norm, i + 1)
      if (next && next !== ';' && next !== ',' && next !== ')' && next !== ']' && next !== '.' && next !== ':') {
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      }
      lastToken = 'expr_start'
      lastWord = ''
      i++
      continue
    }

    // Semicolon
    if (ch === ';') {
      ensureLineStart()
      emitRaw(';')
      if (forParenDepth > 0 || templateBraceStack.length > 0) {
        const next = i + 1 < len ? norm[i + 1] : ''
        if (next && next !== ' ' && next !== '\t' && next !== '\n' && next !== ')') {
          out.push(' ')
        }
      } else {
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      }
      lastToken = 'expr_start'
      lastWord = ''
      i++
      continue
    }

    // Parentheses
    if (ch === '(') {
      ensureLineStart()
      emitRaw('(')
      if (lastWord === 'for' || (lastWord === 'await' && prevWord === 'for')) {
        parenStack.push('for')
        forParenDepth++
      } else if (Object.prototype.hasOwnProperty.call(CONTROL_PAREN_KEYWORDS, lastWord)) {
        parenStack.push('control')
      } else {
        parenStack.push('other')
      }
      lastToken = 'expr_start'
      lastWord = ''
      prevWord = ''
      i++
      continue
    }

    if (ch === ')') {
      ensureLineStart()
      emitRaw(')')
      const popped = parenStack.pop()
      if (popped === 'for') {
        forParenDepth = Math.max(0, forParenDepth - 1)
        lastToken = 'expr_start'
      } else if (popped === 'control') {
        lastToken = 'expr_start'
      } else {
        lastToken = 'expr_end'
      }
      lastWord = ''
      i++
      continue
    }

    // Brackets
    if (ch === '[') {
      ensureLineStart()
      emitRaw('[')
      lastToken = 'expr_start'
      lastWord = ''
      i++
      continue
    }

    if (ch === ']') {
      ensureLineStart()
      emitRaw(']')
      lastToken = 'expr_end'
      lastWord = ''
      i++
      continue
    }

    // ++ and -- preserve expr_end when postfix
    if ((ch === '+' && norm[i + 1] === '+') || (ch === '-' && norm[i + 1] === '-')) {
      ensureLineStart()
      emitRaw(ch + ch)
      // Postfix x++ keeps expr_end; prefix ++x stays expr_start
      lastWord = ''
      i += 2
      continue
    }

    // Arrow =>
    if (ch === '=' && norm[i + 1] === '>') {
      ensureLineStart()
      emitRaw('=>')
      lastToken = 'expr_start'
      lastWord = ''
      i += 2
      continue
    }

    // Other punctuation/operators
    ensureLineStart()
    emitRaw(ch)
    lastToken = 'expr_start'
    lastWord = ''
    i++
  }

  const result = out.join('').replace(/[ \t]+$/gm, '').replace(/\n+$/, '')
  return {
    text: result,
    lineCount: result === '' ? 0 : lineCount,
    exceededCap: false,
  }
}

function beautifyCSS(norm: string, maxLines: number): BeautifyResult {
  const out: string[] = []
  let lineCount = 1
  let indent = 0
  let parenDepth = 0
  let atLineStart = true

  const emitRaw = (s: string) => {
    out.push(s)
    atLineStart = false
  }

  const ensureLineStart = () => {
    if (atLineStart) {
      if (indent > 0) out.push('  '.repeat(indent))
      atLineStart = false
    }
  }

  const trimTrailingHorizontalSpace = () => {
    while (out.length > 0) {
      const last = out[out.length - 1]
      if (last === ' ' || last === '\t') out.pop()
      else break
    }
  }

  const emitNewline = (): boolean => {
    trimTrailingHorizontalSpace()
    out.push('\n')
    lineCount++
    atLineStart = true
    return lineCount > maxLines
  }

  const len = norm.length
  let i = 0

  while (i < len) {
    if (lineCount > maxLines) {
      return { text: norm, lineCount, exceededCap: true }
    }

    const ch = norm[i]

    // Comments /* ... */
    if (ch === '/' && i + 1 < len && norm[i + 1] === '*') {
      ensureLineStart()
      let end = i + 2
      while (end < len) {
        if (norm[end] === '*' && end + 1 < len && norm[end + 1] === '/') {
          end += 2
          break
        }
        if (norm[end] === '\n') {
          lineCount++
          if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
        }
        end++
      }
      emitRaw(norm.slice(i, end))
      i = end
      continue
    }

    // Strings '...' or "..."
    if (ch === '\'' || ch === '"') {
      ensureLineStart()
      const quote = ch
      let end = i + 1
      while (end < len) {
        const c = norm[end]
        if (c === '\\') {
          if (end + 1 < len) {
            if (norm[end + 1] === '\n') {
              lineCount++
              if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
            }
            end += 2
          } else {
            end++
          }
          continue
        }
        if (c === quote) {
          end++
          break
        }
        if (c === '\n') {
          lineCount++
          if (lineCount > maxLines) return { text: norm, lineCount, exceededCap: true }
        }
        end++
      }
      emitRaw(norm.slice(i, end))
      i = end
      continue
    }

    // CSS backslash escape outside strings (e.g. .hover\:bg-red-500)
    if (ch === '\\') {
      ensureLineStart()
      if (i + 1 < len) {
        emitRaw(ch + norm[i + 1])
        i += 2
      } else {
        emitRaw(ch)
        i++
      }
      continue
    }

    // Whitespace
    if (ch === ' ' || ch === '\t') {
      if (!atLineStart) {
        const last = out[out.length - 1]
        if (last && last !== ' ' && last !== '\t' && last !== '\n') {
          out.push(' ')
        }
      }
      i++
      continue
    }

    if (ch === '\n') {
      if (!atLineStart && parenDepth === 0) {
        // Keep selector lines or separate rules clean; avoid double newlines
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
      }
      i++
      continue
    }

    if (ch === '(') {
      ensureLineStart()
      parenDepth++
      emitRaw('(')
      i++
      continue
    }

    if (ch === ')') {
      ensureLineStart()
      parenDepth = Math.max(0, parenDepth - 1)
      emitRaw(')')
      i++
      continue
    }

    if (parenDepth === 0) {
      if (ch === '{') {
        ensureLineStart()
        trimTrailingHorizontalSpace()
        emitRaw(' {')
        indent++
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
        i++
        continue
      }

      if (ch === '}') {
        indent = Math.max(0, indent - 1)
        if (!atLineStart) {
          if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
        }
        ensureLineStart()
        emitRaw('}')
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
        i++
        continue
      }

      if (ch === ';') {
        ensureLineStart()
        trimTrailingHorizontalSpace()
        emitRaw(';')
        if (emitNewline()) return { text: norm, lineCount, exceededCap: true }
        i++
        continue
      }
    }

    ensureLineStart()
    emitRaw(ch)
    i++
  }

  const result = out.join('').replace(/[ \t]+$/gm, '').replace(/\n+$/, '')
  return {
    text: result,
    lineCount: result === '' ? 0 : lineCount,
    exceededCap: false,
  }
}

export function beautifyCode(
  text: string,
  kind: 'js' | 'css',
  maxLines = DEFAULT_MAX_LINES,
): BeautifyResult {
  const norm = normalizeNewlines(text)
  if (!norm) return { text: '', lineCount: 0, exceededCap: false }
  return kind === 'css' ? beautifyCSS(norm, maxLines) : beautifyJS(norm, maxLines)
}

function splitChunkLines(value: string): string[] {
  if (value === '') return []
  const trimmed = value.endsWith('\n') ? value.slice(0, -1) : value
  return trimmed.split('\n')
}

function buildSimplifiedDiff(oldNorm: string, newNorm: string): DiffResult {
  const oldArr = splitChunkLines(oldNorm)
  const newArr = splitChunkLines(newNorm)

  let prefix = 0
  const minLen = Math.min(oldArr.length, newArr.length)
  while (prefix < minLen && oldArr[prefix] === newArr[prefix]) {
    prefix++
  }

  let suffix = 0
  while (
    suffix < oldArr.length - prefix &&
    suffix < newArr.length - prefix &&
    oldArr[oldArr.length - 1 - suffix] === newArr[newArr.length - 1 - suffix]
  ) {
    suffix++
  }

  const blocks: DiffBlock[] = []
  let oldLineNum = 1
  let newLineNum = 1
  let addedLines = 0
  let removedLines = 0
  let totalChanges = 0

  if (prefix > 0) {
    const lines: DiffLine[] = []
    for (let i = 0; i < prefix; i++) {
      lines.push({ kind: 'context', text: oldArr[i], oldLine: oldLineNum++, newLine: newLineNum++ })
    }
    blocks.push({ kind: 'context', lines })
  }

  const oldMidEnd = oldArr.length - suffix
  const newMidEnd = newArr.length - suffix
  if (prefix < oldMidEnd || prefix < newMidEnd) {
    const lines: DiffLine[] = []
    for (let i = prefix; i < oldMidEnd; i++) {
      lines.push({ kind: 'removed', text: oldArr[i], oldLine: oldLineNum++, newLine: null })
      removedLines++
    }
    for (let i = prefix; i < newMidEnd; i++) {
      lines.push({ kind: 'added', text: newArr[i], oldLine: null, newLine: newLineNum++ })
      addedLines++
    }
    blocks.push({ kind: 'change', changeIndex: 0, lines })
    totalChanges = 1
  }

  if (suffix > 0) {
    const lines: DiffLine[] = []
    for (let i = oldMidEnd; i < oldArr.length; i++) {
      lines.push({ kind: 'context', text: oldArr[i], oldLine: oldLineNum++, newLine: newLineNum++ })
    }
    blocks.push({ kind: 'context', lines })
  }

  return {
    blocks,
    totalChanges,
    addedLines,
    removedLines,
    simplified: true,
  }
}

export function buildDiffBlocks(
  oldText: string,
  newText: string,
  options?: BuildDiffOptions,
): DiffResult {
  const oldNorm = normalizeNewlines(oldText)
  const newNorm = normalizeNewlines(newText)

  if (oldNorm === '' && newNorm === '') {
    return { blocks: [], totalChanges: 0, addedLines: 0, removedLines: 0, simplified: false }
  }

  const chunks = diffLines(oldNorm, newNorm, {
    timeout: options?.timeout ?? DEFAULT_DIFF_TIMEOUT,
    maxEditLength: options?.maxEditLength ?? DEFAULT_MAX_EDIT_LENGTH,
  })

  if (chunks === undefined) {
    return buildSimplifiedDiff(oldNorm, newNorm)
  }

  const blocks: DiffBlock[] = []
  let oldLineNum = 1
  let newLineNum = 1
  let changeIndex = 0
  let addedLines = 0
  let removedLines = 0

  for (const chunk of chunks) {
    const rawLines = splitChunkLines(chunk.value)
    if (rawLines.length === 0) continue

    if (chunk.added || chunk.removed) {
      const diffLinesList: DiffLine[] = rawLines.map(text => {
        if (chunk.added) {
          addedLines++
          return { kind: 'added', text, oldLine: null, newLine: newLineNum++ }
        }
        removedLines++
        return { kind: 'removed', text, oldLine: oldLineNum++, newLine: null }
      })

      const prevBlock = blocks[blocks.length - 1]
      if (prevBlock && prevBlock.kind === 'change') {
        prevBlock.lines.push(...diffLinesList)
      } else {
        blocks.push({ kind: 'change', changeIndex: changeIndex++, lines: diffLinesList })
      }
    } else {
      const contextLines: DiffLine[] = rawLines.map(text => ({
        kind: 'context',
        text,
        oldLine: oldLineNum++,
        newLine: newLineNum++,
      }))

      const prevBlock = blocks[blocks.length - 1]
      if (prevBlock && prevBlock.kind === 'context') {
        prevBlock.lines.push(...contextLines)
      } else {
        blocks.push({ kind: 'context', lines: contextLines })
      }
    }
  }

  return {
    blocks,
    totalChanges: changeIndex,
    addedLines,
    removedLines,
    simplified: false,
  }
}

export function foldContextLines(lines: DiffLine[], contextRadius = 3): FoldedContext {
  if (lines.length <= contextRadius * 2) {
    return {
      collapsed: false,
      top: lines,
      hidden: [],
      bottom: [],
    }
  }
  return {
    collapsed: true,
    top: lines.slice(0, contextRadius),
    hidden: lines.slice(contextRadius, lines.length - contextRadius),
    bottom: lines.slice(lines.length - contextRadius),
  }
}
