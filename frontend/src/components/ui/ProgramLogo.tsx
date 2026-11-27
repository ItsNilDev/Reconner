import { useEffect, useState } from 'react'
import { cn } from '../../lib/utils'

interface ProgramLogoProps {
  src?: string
  name: string
  size?: 'sm' | 'md'
  className?: string
}

const SIZE_CLASSES: Record<'sm' | 'md', string> = {
  sm: 'w-7 h-7 rounded-lg text-xs',
  md: 'w-10 h-10 rounded-xl text-sm',
}

function safeLogoUrl(raw?: string): string {
  const trimmed = (raw || '').trim()
  if (!trimmed || !/^https?:\/\/[^/\s]/i.test(trimmed)) return ''
  try {
    const u = new URL(trimmed)
    if ((u.protocol === 'http:' || u.protocol === 'https:') && u.host) {
      return trimmed
    }
  } catch {
    // invalid URL
  }
  return ''
}

export function ProgramLogo({ src, name, size = 'md', className }: ProgramLogoProps) {
  const safeSrc = safeLogoUrl(src)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    setFailed(false)
  }, [safeSrc])

  const cleaned = (name || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/^(?:\*\.)+/, '')
    .trim()
  const initial = (Array.from(cleaned)[0] || '?').toUpperCase()

  return (
    <div
      className={cn(
        'border border-white/[.07] bg-white/[.03] grid place-items-center shrink-0 overflow-hidden',
        SIZE_CLASSES[size],
        className,
      )}
    >
      {safeSrc && !failed ? (
        <img
          src={safeSrc}
          alt=""
          referrerPolicy="no-referrer"
          loading="lazy"
          decoding="async"
          onError={() => setFailed(true)}
          className="w-full h-full object-contain"
        />
      ) : (
        <span className="font-bold text-text-muted">{initial}</span>
      )}
    </div>
  )
}
