'use client'

import { useEffect, useRef, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { getAuthState } from '@/lib/auth'
import Link from 'next/link'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

interface Resource {
  id: string
  name: string
  resource_type: string
}

interface Session {
  session_token: string
  websocket_url: string
}

export default function ConnectPage() {
  const params = useParams()
  const router = useRouter()
  const terminalRef = useRef<HTMLDivElement>(null)
  const terminalInstance = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  const [resource, setResource] = useState<Resource | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting')
  const [error, setError] = useState('')

  useEffect(() => {
    initializeConnection()
    return () => {
      cleanup()
    }
  }, [params.id])

  const initializeConnection = async () => {
    try {
      const token = getAuthState()?.token
      if (!token) {
        router.push('/login')
        return
      }

      // Fetch resource details
      const resourceRes = await fetch(`/api/v1/resources/${params.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resourceRes.ok) throw new Error('Resource not found')
      const resourceData = await resourceRes.json()
      setResource(resourceData)

      // Request session
      const sessionRes = await fetch('/api/v1/connect/session', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          resource_id: params.id,
          protocol: resourceData.resource_type,
        }),
      })
      if (!sessionRes.ok) throw new Error('Failed to create session')
      const sessionData = await sessionRes.json()
      setSession(sessionData)

      // Initialize terminal
      if (terminalRef.current && resourceData.resource_type === 'ssh') {
        initializeTerminal(sessionData)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed')
      setStatus('error')
    }
  }

  const initializeTerminal = (sessionData: Session) => {
    if (!terminalRef.current) return

    const terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1e293b',
        foreground: '#e2e8f0',
        cursor: '#e2e8f0',
      },
    })

    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    terminal.open(terminalRef.current)
    fitAddon.fit()

    terminalInstance.current = terminal

    // Connect WebSocket
    const wsUrl = sessionData.websocket_url ||
      `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/session/${sessionData.session_token}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setStatus('connected')
      terminal.write('Connected to ' + resource?.name + '\r\n\r\n')
    }

    ws.onmessage = (event) => {
      terminal.write(event.data)
    }

    ws.onclose = () => {
      setStatus('disconnected')
      terminal.write('\r\n\r\n[Connection closed]\r\n')
    }

    ws.onerror = () => {
      setStatus('error')
      setError('WebSocket connection failed')
    }

    terminal.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data)
      }
    })

    // Handle resize
    const handleResize = () => {
      fitAddon.fit()
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'resize',
          cols: terminal.cols,
          rows: terminal.rows,
        }))
      }
    }

    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
    }
  }

  const cleanup = () => {
    if (wsRef.current) {
      wsRef.current.close()
    }
    if (terminalInstance.current) {
      terminalInstance.current.dispose()
    }
  }

  const statusColors = {
    connecting: 'text-yellow-500',
    connected: 'text-green-500',
    disconnected: 'text-gray-500',
    error: 'text-red-500',
  }

  return (
    <main className="min-h-screen flex flex-col">
      <header className="flex justify-between items-center p-4 bg-slate-800 border-b border-slate-700">
        <div className="flex items-center gap-4">
          <Link href="/" className="text-slate-400 hover:text-brand-400 transition-colors">
            ← Resources
          </Link>
          {resource && (
            <span className="font-medium">{resource.name}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${
            status === 'connected' ? 'bg-green-500' :
            status === 'connecting' ? 'bg-yellow-500 animate-pulse' :
            status === 'error' ? 'bg-red-500' : 'bg-gray-500'
          }`}></span>
          <span className={`text-sm ${statusColors[status]}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </span>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-red-900/30 text-red-400 text-center">
          {error}
        </div>
      )}

      <div ref={terminalRef} className="flex-1 bg-slate-900 p-2" />
    </main>
  )
}
