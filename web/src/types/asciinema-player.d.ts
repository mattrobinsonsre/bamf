declare module 'asciinema-player' {
  interface PlayerOptions {
    cols?: number
    rows?: number
    autoPlay?: boolean
    preload?: boolean
    loop?: boolean | number
    startAt?: number | string
    speed?: number
    idleTimeLimit?: number
    theme?: string
    poster?: string
    fit?: 'width' | 'height' | 'both' | 'none' | false
    controls?: boolean | 'auto'
    markers?: [number, string][]
    pauseOnMarkers?: boolean
    terminalFontSize?: string
    terminalFontFamily?: string
    terminalLineHeight?: number
    logger?: Console
  }

  interface Player {
    dispose(): void
    getCurrentTime(): number
    getDuration(): number
    play(): void
    pause(): void
    seek(location: number | string): void
  }

  export function create(
    src: string | { data: string } | { url: string },
    element: HTMLElement,
    options?: PlayerOptions,
  ): Player
}
