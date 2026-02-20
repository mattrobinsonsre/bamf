'use client'

import { useEffect, useRef } from 'react'
import type { Player } from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'

interface RecordingPlayerProps {
  recording: string
}

export default function RecordingPlayer({ recording }: RecordingPlayerProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const playerRef = useRef<Player | null>(null)

  useEffect(() => {
    if (!containerRef.current || !recording) return

    let disposed = false

    // Dynamic import — asciinema-player has no SSR support
    import('asciinema-player').then((AsciinemaPlayer) => {
      if (disposed || !containerRef.current) return

      // Create a blob URL from the recording data
      const blob = new Blob([recording], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)

      playerRef.current = AsciinemaPlayer.create(url, containerRef.current, {
        theme: 'monokai',
        fit: 'width',
        autoPlay: false,
        terminalFontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      })

      return () => {
        URL.revokeObjectURL(url)
      }
    })

    return () => {
      disposed = true
      if (playerRef.current) {
        playerRef.current.dispose()
        playerRef.current = null
      }
    }
  }, [recording])

  return (
    <div className="rounded-lg overflow-hidden border border-slate-700/50">
      <div ref={containerRef} />
    </div>
  )
}
