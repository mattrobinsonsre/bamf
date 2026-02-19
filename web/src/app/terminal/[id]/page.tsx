'use client'

import { useCallback, useEffect, useState } from 'react'
import { useParams, useRouter, useSearchParams } from 'next/navigation'
import { ArrowLeft, Terminal } from 'lucide-react'
import WebTerminal from '@/components/web-terminal'
import TerminalConnectDialog, { type ConnectData } from '@/components/terminal-connect-dialog'
import { clearAuth, getAuthState } from '@/lib/auth'

export default function TerminalPage() {
  const params = useParams()
  const searchParams = useSearchParams()
  const router = useRouter()

  const paramId = params.id as string
  const resourceType = searchParams.get('type') || 'ssh'
  const resourceName = searchParams.get('resource') || paramId

  // sessionId is null until POST /connect succeeds (when paramId is "new")
  const [sessionId, setSessionId] = useState<string | null>(paramId === 'new' ? null : paramId)
  const [phase, setPhase] = useState<'dialog' | 'connecting' | 'terminal' | 'error'>('dialog')
  const [credentials, setCredentials] = useState<ConnectData | null>(null)
  const [errorMsg, setErrorMsg] = useState('')

  useEffect(() => {
    const auth = getAuthState()
    if (!auth) {
      router.push('/login')
    }
  }, [router])

  const handleConnect = useCallback(async (data: ConnectData) => {
    setCredentials(data)

    // If we already have a session (legacy URL with session ID), go straight to terminal
    if (sessionId) {
      setPhase('terminal')
      return
    }

    // Create session now — right when the user clicks Connect
    setPhase('connecting')
    const auth = getAuthState()
    if (!auth) {
      router.push('/login')
      return
    }

    const isSSH = ['ssh', 'ssh-audit'].includes(resourceType)
    const protocol = isSSH ? 'web-ssh' : 'web-db'

    try {
      const resp = await fetch('/api/v1/connect', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${auth.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ resource_name: resourceName, protocol }),
      })

      if (resp.status === 401) {
        clearAuth()
        router.push('/login')
        return
      }

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: 'Connection failed' }))
        setErrorMsg(errData.detail || 'Connection failed')
        setPhase('error')
        return
      }

      const result = await resp.json()
      setSessionId(result.session_id)
      setPhase('terminal')
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Connection failed')
      setPhase('error')
    }
  }, [sessionId, resourceType, resourceName, router])

  const handleCancel = useCallback(() => {
    router.back()
  }, [router])

  const handleError = useCallback((msg: string) => {
    setErrorMsg(msg)
    setPhase('error')
  }, [])

  // Determine the bridge protocol from the native resource type
  const isSSH = resourceType === 'ssh' || resourceType === 'ssh-audit' || resourceType === 'web-ssh'
  const webResourceType = isSSH ? 'web-ssh' : 'web-db'

  return (
    <div className="h-screen flex flex-col bg-[#0f172a]">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2 bg-slate-800 border-b border-slate-700">
        <button
          onClick={() => router.back()}
          className="p-1 text-slate-400 hover:text-slate-200 transition-colors"
          title="Back"
        >
          <ArrowLeft size={18} />
        </button>
        <Terminal size={16} className="text-slate-400" />
        <span className="text-sm font-medium text-slate-200">{resourceName}</span>
        <span className="text-xs text-slate-500 bg-slate-700/50 px-2 py-0.5 rounded">
          {resourceType}
        </span>
        <div className="flex-1" />
        <button
          onClick={() => {
            router.back()
          }}
          className="text-xs text-slate-400 hover:text-red-400 transition-colors px-2 py-1"
        >
          Disconnect
        </button>
      </div>

      {/* Dialog phase */}
      {phase === 'dialog' && (
        <TerminalConnectDialog
          resourceType={resourceType}
          resourceName={resourceName}
          onConnect={handleConnect}
          onCancel={handleCancel}
        />
      )}

      {/* Connecting phase */}
      {phase === 'connecting' && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-400">Connecting...</p>
          </div>
        </div>
      )}

      {/* Terminal phase */}
      {phase === 'terminal' && credentials && sessionId && (
        <div className="flex-1">
          <WebTerminal
            sessionId={sessionId}
            resourceType={webResourceType}
            credentials={credentials}
            onError={handleError}
          />
        </div>
      )}

      {/* Error phase */}
      {phase === 'error' && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <p className="text-red-400 mb-4">{errorMsg}</p>
            <button
              onClick={() => { setPhase('dialog'); setSessionId(null) }}
              className="px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
