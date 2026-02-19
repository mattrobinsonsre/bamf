'use client'

import { useEffect, useRef, useState } from 'react'
import { clearAuth, getAuthState } from '@/lib/auth'

/**
 * WebTerminal — xterm.js terminal with auto-reconnect.
 *
 * Connects to the API WebSocket relay, which forwards to the bridge.
 * On disconnect (not user-initiated), attempts exponential backoff reconnect.
 */

import { type ConnectData } from '@/components/terminal-connect-dialog'

interface WebTerminalProps {
  sessionId: string
  resourceType: string // web-ssh or web-db
  credentials: ConnectData // initial connect message sent on WS open
  onConnected?: () => void
  onDisconnected?: () => void
  onError?: (message: string) => void
}

export default function WebTerminal({
  sessionId,
  resourceType,
  credentials,
  onConnected,
  onDisconnected,
  onError,
}: WebTerminalProps) {
  const termRef = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<import('@xterm/xterm').Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const fitAddonRef = useRef<import('@xterm/addon-fit').FitAddon | null>(null)
  const [status, setStatus] = useState<'connecting' | 'connected' | 'reconnecting' | 'disconnected'>('connecting')
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 3
  const userDisconnected = useRef(false)

  // Use refs for callbacks to avoid recreating the connect function
  const onConnectedRef = useRef(onConnected)
  const onDisconnectedRef = useRef(onDisconnected)
  const onErrorRef = useRef(onError)
  onConnectedRef.current = onConnected
  onDisconnectedRef.current = onDisconnected
  onErrorRef.current = onError

  // Store credentials and other props in refs so connect doesn't depend on them
  const credentialsRef = useRef(credentials)
  credentialsRef.current = credentials

  // Use a ref for the connect function so the effect doesn't re-run
  const connectRef = useRef<(() => Promise<void>) | undefined>(undefined)

  useEffect(() => {
    let mounted = true

    async function getTicket(): Promise<string | null> {
      const auth = getAuthState()
      if (!auth) return null

      try {
        const resp = await fetch('/api/v1/terminal/ticket', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${auth.token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ session_id: sessionId }),
        })
        if (resp.status === 401) {
          clearAuth()
          window.location.href = '/login'
          return null
        }
        if (!resp.ok) return null
        const data = await resp.json()
        return data.ticket
      } catch {
        return null
      }
    }

    async function connect() {
      if (!mounted) return

      const ticket = await getTicket()
      if (!ticket) {
        setStatus('disconnected')
        onErrorRef.current?.('Failed to get WebSocket ticket')
        return
      }

      const wsPath = resourceType === 'web-ssh' ? 'ssh' : 'db'
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${window.location.host}/api/v1/terminal/${wsPath}/${sessionId}?ticket=${ticket}`

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.binaryType = 'arraybuffer'

      ws.onopen = () => {
        // Send initial credentials message
        ws.send(JSON.stringify(credentialsRef.current))
      }

      ws.onmessage = (event) => {
        const terminal = terminalRef.current
        if (!terminal) return

        if (event.data instanceof ArrayBuffer) {
          // Binary: terminal data from bridge
          const bytes = new Uint8Array(event.data)
          terminal.write(bytes)
        } else if (typeof event.data === 'string') {
          // Text: control message
          try {
            const msg = JSON.parse(event.data)
            if (msg.type === 'status') {
              if (msg.status === 'ready') {
                setStatus('connected')
                reconnectAttempts.current = 0
                onConnectedRef.current?.()
              } else if (msg.status === 'detached') {
                terminal.write('\r\n[Session detached - waiting for reconnect...]\r\n')
              } else if (msg.status === 'resumed') {
                terminal.write('\r\n[Session resumed]\r\n')
              }
            } else if (msg.type === 'error') {
              onErrorRef.current?.(msg.message || 'Unknown error')
              setStatus('disconnected')
            }
          } catch {
            // Ignore non-JSON text messages
          }
        }
      }

      ws.onclose = () => {
        if (userDisconnected.current) {
          setStatus('disconnected')
          onDisconnectedRef.current?.()
          return
        }

        // Not user-initiated — try reconnect
        if (reconnectAttempts.current < maxReconnectAttempts) {
          setStatus('reconnecting')
          const terminal = terminalRef.current
          if (terminal) {
            terminal.write('\r\n[Reconnecting...]\r\n')
          }

          const delay = Math.min(500 * Math.pow(2, reconnectAttempts.current), 4000)
          reconnectAttempts.current++

          setTimeout(() => {
            connectRef.current?.()
          }, delay)
        } else {
          setStatus('disconnected')
          const terminal = terminalRef.current
          if (terminal) {
            terminal.write('\r\n[Disconnected - click to reconnect]\r\n')
          }
          onDisconnectedRef.current?.()
        }
      }

      ws.onerror = () => {
        // onclose will fire after onerror
      }
    }

    connectRef.current = connect

    async function init() {
      if (!termRef.current || !mounted) return

      // Dynamic import to avoid SSR issues with xterm
      const { Terminal } = await import('@xterm/xterm')
      const { FitAddon } = await import('@xterm/addon-fit')
      const { WebLinksAddon } = await import('@xterm/addon-web-links')

      // Import xterm CSS
      await import('@xterm/xterm/css/xterm.css')

      if (!mounted || !termRef.current) return

      const fitAddon = new FitAddon()
      fitAddonRef.current = fitAddon

      const terminal = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        theme: {
          background: '#0f172a',
          foreground: '#e2e8f0',
          cursor: '#e2e8f0',
          selectionBackground: '#334155',
        },
      })

      terminal.loadAddon(fitAddon)
      terminal.loadAddon(new WebLinksAddon())

      terminal.open(termRef.current)

      // Delay fit to ensure the container has dimensions
      requestAnimationFrame(() => {
        if (mounted) fitAddon.fit()
      })

      terminalRef.current = terminal

      // Handle terminal input — send as binary via WebSocket
      terminal.onData((data) => {
        const ws = wsRef.current
        if (ws && ws.readyState === WebSocket.OPEN) {
          const encoder = new TextEncoder()
          ws.send(encoder.encode(data))
        }
      })

      // Handle terminal resize
      terminal.onResize(({ cols, rows }) => {
        const ws = wsRef.current
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols, rows }))
        }
      })

      // Connect
      connect()
    }

    init()

    // Handle window resize
    const handleResize = () => {
      fitAddonRef.current?.fit()
    }
    window.addEventListener('resize', handleResize)

    return () => {
      mounted = false
      window.removeEventListener('resize', handleResize)
      userDisconnected.current = true
      wsRef.current?.close()
      terminalRef.current?.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, resourceType])

  return (
    <div className="flex flex-col h-full">
      {status === 'reconnecting' && (
        <div className="px-3 py-1 bg-yellow-900/30 text-yellow-400 text-xs text-center border-b border-yellow-800/50">
          Reconnecting...
        </div>
      )}
      <div ref={termRef} className="flex-1 bg-[#0f172a]" />
    </div>
  )
}
